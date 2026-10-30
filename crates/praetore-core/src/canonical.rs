use serde::{
    Deserialize, Serialize,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::fmt;

pub const CANONICAL_VERSION: u8 = 1;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_JSON_VALUE_BYTES: usize = 65_536;
const MAX_JSON_NODES: usize = 16_384;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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

pub fn parse_json_rejecting_duplicates(input: &str) -> Result<Value, String> {
    if input.len() > MAX_JSON_VALUE_BYTES {
        return Err("JSON input exceeds maximum size".into());
    }
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| error.to_string())?
        .0;
    deserializer.end().map_err(|error| error.to_string())?;
    validate_json_value(&value).map_err(str::to_owned)?;
    Ok(value)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
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
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number is not supported"))?;
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
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
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
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    validate_json_value(&value).map_err(<serde_json::Error as serde::ser::Error>::custom)?;
    let mut output = Vec::new();
    write_value(&value, &mut output)?;
    if output.len() > MAX_JSON_VALUE_BYTES {
        return Err(<serde_json::Error as serde::ser::Error>::custom(
            "canonical JSON exceeds maximum size",
        ));
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

pub(crate) fn validate_json_value(value: &Value) -> Result<usize, &'static str> {
    let mut pending = vec![(value, 1usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;

    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_JSON_NODES {
            return Err("JSON value exceeds maximum node count");
        }
        if depth > MAX_JSON_DEPTH {
            return Err("JSON value exceeds maximum nesting depth");
        }

        match value {
            Value::Null | Value::Bool(_) => bytes += 5,
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    if value.unsigned_abs() > MAX_SAFE_INTEGER {
                        return Err("JSON integer exceeds interoperable safe range");
                    }
                } else if let Some(value) = number.as_u64() {
                    if value > MAX_SAFE_INTEGER {
                        return Err("JSON integer exceeds interoperable safe range");
                    }
                } else if number.as_f64().is_some_and(|value| {
                    value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64
                }) {
                    return Err("JSON integral number exceeds interoperable safe range");
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
            return Err("JSON value exceeds maximum size");
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
        MAX_JSON_DEPTH, canonical_json, parse_json_rejecting_duplicates, validate_json_value,
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
        assert!(validate_json_value(&unsafe_integer).is_err());

        let mut nested = serde_json::json!(null);
        for _ in 0..=MAX_JSON_DEPTH {
            nested = serde_json::json!([nested]);
        }
        assert!(validate_json_value(&nested).is_err());
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
