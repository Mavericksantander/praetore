use serde::{
    Serialize,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{cell::Cell, fmt};

pub const CANONICAL_VERSION: u8 = 1;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_VALUE_BYTES: usize = 65_536;
pub const MAX_JSON_NODES: usize = 16_384;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Why a JSON document was rejected by the strict parser, the structural
/// validator or the canonical encoder. Callers map it to their own error
/// type without inspecting messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// The raw input is longer than `MAX_JSON_VALUE_BYTES`.
    #[error("JSON input exceeds maximum size")]
    InputTooLarge,
    /// The input is not a single well-formed JSON value.
    #[error("malformed JSON at line {line} column {column}")]
    Malformed { line: usize, column: usize },
    /// An object, at any depth, repeats a key.
    #[error("duplicate JSON object key")]
    DuplicateKey,
    /// The decoded value is larger than `MAX_JSON_VALUE_BYTES`.
    #[error("JSON value exceeds maximum size")]
    ValueTooLarge,
    /// The value nests deeper than `MAX_JSON_DEPTH`.
    #[error("JSON value exceeds maximum nesting depth")]
    TooDeep,
    /// The value has more than `MAX_JSON_NODES` nodes.
    #[error("JSON value exceeds maximum node count")]
    TooManyNodes,
    /// An integer, or an integral float, outside +/-`MAX_SAFE_INTEGER`.
    #[error("JSON integer exceeds interoperable safe range")]
    UnsafeInteger,
    /// The canonical encoding is longer than `MAX_JSON_VALUE_BYTES`.
    #[error("canonical JSON exceeds maximum size")]
    CanonicalTooLarge,
    /// The value could not be converted to a JSON value.
    #[error("value cannot be represented as JSON")]
    Unrepresentable,
}

/// Decodes lowercase hexadecimal only, the single encoding `hex::encode`
/// emits. Signatures, digests and key ids have one valid textual form, so
/// uppercase or mixed case is rejected rather than silently accepted.
pub(crate) fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        hex::decode(value).ok()
    } else {
        None
    }
}

/// Parses `input` as one JSON value, rejecting oversized input, duplicate
/// object keys at any depth and values outside the structural limits.
///
/// Kept for callers that report a message; its messages are unchanged.
/// New code should prefer [`parse_json_strict`], which returns a typed error.
pub fn parse_json_rejecting_duplicates(input: &str) -> Result<Value, String> {
    parse_json(input).map_err(|(_, message)| message)
}

/// Same checks as [`parse_json_rejecting_duplicates`], with a typed error.
pub fn parse_json_strict(input: &str) -> Result<Value, JsonError> {
    parse_json(input).map_err(|(error, _)| error)
}

/// Returns the typed reason together with the message the string API has
/// always reported (serde's own text for syntax errors).
fn parse_json(input: &str) -> Result<Value, (JsonError, String)> {
    if input.len() > MAX_JSON_VALUE_BYTES {
        let error = JsonError::InputTooLarge;
        return Err((error, error.to_string()));
    }
    let rejected = Cell::new(None);
    let syntax_error = |error: serde_json::Error, rejected: &Cell<Option<JsonError>>| {
        let typed = rejected.get().unwrap_or(JsonError::Malformed {
            line: error.line(),
            column: error.column(),
        });
        (typed, error.to_string())
    };
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = UniqueValueSeed {
        rejected: &rejected,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| syntax_error(error, &rejected))?
    .0;
    deserializer
        .end()
        .map_err(|error| syntax_error(error, &rejected))?;
    validate_json_value(&value).map_err(|error| (error, error.to_string()))?;
    Ok(value)
}

struct UniqueValue(Value);

/// Deserializes a [`UniqueValue`] and records in `rejected` why it refused
/// the input, so the caller gets a typed reason instead of serde's message.
#[derive(Clone, Copy)]
struct UniqueValueSeed<'a> {
    rejected: &'a Cell<Option<JsonError>>,
}

impl<'de> DeserializeSeed<'de> for UniqueValueSeed<'_> {
    type Value = UniqueValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueValueSeed<'_> {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_unit()
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let number = serde_json::Number::from_f64(value).ok_or_else(|| {
            self.rejected.set(Some(JsonError::Unrepresentable));
            E::custom("non-finite JSON number is not supported")
        })?;
        Ok(UniqueValue(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self)? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                self.rejected.set(Some(JsonError::DuplicateKey));
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(self)?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, JsonError> {
    let value = serde_json::to_value(value).map_err(|_| JsonError::Unrepresentable)?;
    validate_json_value(&value)?;
    let mut output = Vec::new();
    write_value(&value, &mut output).map_err(|_| JsonError::Unrepresentable)?;
    if output.len() > MAX_JSON_VALUE_BYTES {
        return Err(JsonError::CanonicalTooLarge);
    }
    Ok(output)
}

/// Accepts only the canonical encoding of an Ed25519 signature produced by
/// `hex::encode`: exactly 64 bytes as 128 lowercase hex digits. Uppercase or
/// mixed case is rejected so each signed document has a single valid
/// encoding. Shared by evidence and execution-attestation signatures.
pub fn is_canonical_signature_hex(signature: &str) -> bool {
    signature.len() == 128
        && signature
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn canonicalize_json(input: &str) -> crate::Result<Vec<u8>> {
    let value =
        parse_json_rejecting_duplicates(input).map_err(crate::PraetoreError::InvalidRequest)?;
    canonical_json(&value).map_err(|error| {
        crate::PraetoreError::InvalidRequest(format!("canonical JSON encoding failed: {error}"))
    })
}

pub(crate) fn validate_json_value(value: &Value) -> Result<usize, JsonError> {
    let mut pending = vec![(value, 1usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;

    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_JSON_NODES {
            return Err(JsonError::TooManyNodes);
        }
        if depth > MAX_JSON_DEPTH {
            return Err(JsonError::TooDeep);
        }

        match value {
            Value::Null | Value::Bool(_) => bytes += 5,
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    if value.unsigned_abs() > MAX_SAFE_INTEGER {
                        return Err(JsonError::UnsafeInteger);
                    }
                } else if let Some(value) = number.as_u64() {
                    if value > MAX_SAFE_INTEGER {
                        return Err(JsonError::UnsafeInteger);
                    }
                } else if number.as_f64().is_some_and(|value| {
                    value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64
                }) {
                    return Err(JsonError::UnsafeInteger);
                }
                bytes += number.to_string().len();
            }
            Value::String(value) => bytes += value.len(),
            Value::Array(values) => {
                bytes += values.len();
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                bytes += values.len();
                for (key, value) in values {
                    bytes += key.len();
                    pending.push((value, depth + 1));
                }
            }
        }

        if bytes > MAX_JSON_VALUE_BYTES {
            return Err(JsonError::ValueTooLarge);
        }
    }

    Ok(bytes)
}

fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => serde_json::to_writer(output, value)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));

            output.push(b'{');
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        JsonError, MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_VALUE_BYTES, canonical_json,
        parse_json_rejecting_duplicates, parse_json_strict, validate_json_value,
    };

    #[test]
    fn object_key_order_does_not_change_canonical_encoding() {
        let first: serde_json::Value =
            serde_json::from_str(r#"{"z":1,"nested":{"b":2,"a":3},"a":4}"#).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(r#"{"a":4,"nested":{"a":3,"b":2},"z":1}"#).unwrap();

        assert_eq!(
            canonical_json(&first).unwrap(),
            canonical_json(&second).unwrap()
        );
    }

    #[test]
    fn rejects_unsafe_integer_and_excessive_depth() {
        let unsafe_integer = serde_json::json!(9_007_199_254_740_992_u64);
        assert_eq!(
            validate_json_value(&unsafe_integer),
            Err(JsonError::UnsafeInteger)
        );
        assert_eq!(
            validate_json_value(&serde_json::json!(-9_007_199_254_740_992_i64)),
            Err(JsonError::UnsafeInteger)
        );
        assert_eq!(
            validate_json_value(&serde_json::json!(9_007_199_254_740_992.0_f64)),
            Err(JsonError::UnsafeInteger)
        );

        let mut nested = serde_json::json!(null);
        for _ in 0..=MAX_JSON_DEPTH {
            nested = serde_json::json!([nested]);
        }
        assert_eq!(validate_json_value(&nested), Err(JsonError::TooDeep));
        assert_eq!(canonical_json(&nested), Err(JsonError::TooDeep));
    }

    #[test]
    fn strict_parser_reports_each_rejection_as_a_typed_error() {
        assert_eq!(
            parse_json_strict(&" ".repeat(MAX_JSON_VALUE_BYTES + 1)),
            Err(JsonError::InputTooLarge)
        );
        assert_eq!(
            parse_json_strict(r#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey)
        );
        assert_eq!(
            parse_json_strict(r#"{"nested":[{"a":1,"a":2}]}"#),
            Err(JsonError::DuplicateKey)
        );
        assert_eq!(
            parse_json_strict("{\"a\":1,}"),
            Err(JsonError::Malformed { line: 1, column: 8 })
        );
        assert_eq!(
            parse_json_strict("{} {}"),
            Err(JsonError::Malformed { line: 1, column: 4 })
        );
        assert_eq!(
            parse_json_strict("9007199254740992"),
            Err(JsonError::UnsafeInteger)
        );
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert_eq!(parse_json_strict(&deep), Err(JsonError::TooDeep));
        let many = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
        assert_eq!(parse_json_strict(&many), Err(JsonError::TooManyNodes));
    }

    #[test]
    fn canonical_encoder_reports_oversized_output_as_a_typed_error() {
        // The structural estimate counts string bytes without quotes, so a
        // string of exactly the limit passes validation but its canonical
        // encoding (with quotes) is two bytes over.
        let value = serde_json::json!("v".repeat(MAX_JSON_VALUE_BYTES));
        assert!(validate_json_value(&value).is_ok());
        assert_eq!(canonical_json(&value), Err(JsonError::CanonicalTooLarge));
        let value = serde_json::json!("v".repeat(MAX_JSON_VALUE_BYTES + 1));
        assert_eq!(validate_json_value(&value), Err(JsonError::ValueTooLarge));
    }

    #[test]
    fn string_parser_keeps_its_historical_messages() {
        let error = parse_json_rejecting_duplicates(r#"{"a":1,"a":2}"#).unwrap_err();
        assert!(error.starts_with("duplicate JSON object key"), "{error}");
        let error = parse_json_rejecting_duplicates("{").unwrap_err();
        assert!(error.starts_with("EOF while parsing"), "{error}");
    }

    #[test]
    fn rejects_duplicate_object_keys_at_any_depth() {
        assert!(parse_json_rejecting_duplicates(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_json_rejecting_duplicates(r#"{"nested":{"a":1,"a":2}}"#).is_err());
        assert_eq!(
            parse_json_rejecting_duplicates(r#"{"a":[1,2],"b":true}"#).unwrap(),
            serde_json::json!({"a": [1, 2], "b": true})
        );
    }
}
