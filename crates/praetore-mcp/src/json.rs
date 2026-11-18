//! A small order-preserving JSON value that rejects duplicate object keys.
//!
//! Two uses:
//! * client configuration files, so `install`/`uninstall` keep the user's
//!   key order instead of re-sorting the whole document;
//! * classifying untrusted MCP traffic. Rejecting duplicate keys closes a
//!   parser differential: `{"method":"tools/list","method":"tools/call"}`
//!   could be read as `tools/list` here and as `tools/call` by the server.
//!
//! The workspace `serde_json` is built without `preserve_order`, and enabling
//! it would change map ordering for every crate in the workspace, so this
//! type is kept local. `serde_json`'s recursion limit still applies.
//!
//! A number keeps the text it was written with ([`JsonNumber`]). The proxy
//! forwards the client's bytes, so the server parses that text itself; the
//! gate may only decide on a number whose text every parser reads alike.

use serde::{
    Deserializer, Serialize, Serializer,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use std::{cell::Cell, fmt};

/// A JSON number together with the literal it was parsed from.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNumber {
    value: serde_json::Number,
    literal: String,
}

impl JsonNumber {
    /// The parsed value (correctly rounded: `serde_json` is built with
    /// `float_roundtrip`).
    pub fn value(&self) -> &serde_json::Number {
        &self.value
    }

    /// The number as written in the document.
    pub fn literal(&self) -> &str {
        &self.literal
    }

    /// Whether the literal is exactly what this value serializes to. Only
    /// then is the value the gate evaluates the one any other parser gets
    /// from the same bytes: `49.9999999999999965` (an f64 parser reads
    /// 50.0, a decimal parser reads it as written), `1e2`, `-0` and an
    /// integer beyond `u64` are not canonical.
    pub fn is_canonical(&self) -> bool {
        self.value.to_string() == self.literal
    }
}

/// The number literals of `input`, in document order. `input` is checked to
/// be JSON by the parse that consumes this list; outside a string, only a
/// number starts with `-` or a digit.
fn number_literals(input: &str) -> Vec<&str> {
    let bytes = input.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index += 1;
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E')
                {
                    index += 1;
                }
                literals.push(&input[start..index]);
            }
            _ => index += 1,
        }
    }
    literals
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Parses one complete JSON document, rejecting duplicate keys and
    /// trailing data.
    pub fn parse(input: &str) -> Result<Self, String> {
        let literals = number_literals(input);
        let seed = Seed {
            literals: &literals,
            next: &Cell::new(0),
        };
        let mut deserializer = serde_json::Deserializer::from_str(input);
        let value = seed
            .deserialize(&mut deserializer)
            .map_err(|e| e.to_string())?;
        deserializer.end().map_err(|e| e.to_string())?;
        Ok(value)
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonValue> {
        match self {
            JsonValue::Object(entries) => {
                entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Sets `key`, replacing an existing value in place (keeping its
    /// position) or inserting after `after` (or at the end).
    pub fn set(&mut self, key: &str, value: JsonValue, after: Option<&str>) {
        let JsonValue::Object(entries) = self else {
            return;
        };
        if let Some(slot) = entries.iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
            return;
        }
        let position = after
            .and_then(|after| entries.iter().position(|(k, _)| k == after))
            .map(|index| index + 1)
            .unwrap_or(entries.len());
        entries.insert(position, (key.to_owned(), value));
    }

    pub fn remove(&mut self, key: &str) -> Option<JsonValue> {
        let JsonValue::Object(entries) = self else {
            return None;
        };
        let index = entries.iter().position(|(k, _)| k == key)?;
        Some(entries.remove(index).1)
    }

    /// Converts to a `serde_json::Value` (object keys become sorted).
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            JsonValue::Null => serde_json::Value::Null,
            JsonValue::Bool(value) => serde_json::Value::Bool(*value),
            JsonValue::Number(number) => serde_json::Value::Number(number.value.clone()),
            JsonValue::String(value) => serde_json::Value::String(value.clone()),
            JsonValue::Array(values) => {
                serde_json::Value::Array(values.iter().map(JsonValue::to_value).collect())
            }
            JsonValue::Object(entries) => serde_json::Value::Object(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_value()))
                    .collect(),
            ),
        }
    }

    pub fn string(value: impl Into<String>) -> Self {
        JsonValue::String(value.into())
    }

    pub fn to_pretty(&self) -> String {
        // Serializing this type cannot fail: keys are strings and a number
        // literal was accepted by the JSON parser.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn to_compact(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl Serialize for JsonValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JsonValue::Null => serializer.serialize_unit(),
            JsonValue::Bool(value) => serializer.serialize_bool(*value),
            // The literal, so a document is written back as it was read.
            JsonValue::Number(number) => {
                match serde_json::value::RawValue::from_string(number.literal.clone()) {
                    Ok(raw) => raw.serialize(serializer),
                    Err(_) => number.value.serialize(serializer),
                }
            }
            JsonValue::String(value) => serializer.serialize_str(value),
            JsonValue::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            JsonValue::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// Deserializes a [`JsonValue`], giving each number the next literal of the
/// document. Numbers are visited in document order.
#[derive(Clone, Copy)]
struct Seed<'a> {
    literals: &'a [&'a str],
    next: &'a Cell<usize>,
}

impl Seed<'_> {
    fn number<E: serde::de::Error>(self, value: serde_json::Number) -> Result<JsonValue, E> {
        let index = self.next.get();
        self.next.set(index + 1);
        let literal = self
            .literals
            .get(index)
            .ok_or_else(|| E::custom("a number has no literal in the document"))?;
        Ok(JsonValue::Number(JsonNumber {
            value,
            literal: (*literal).to_owned(),
        }))
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = JsonValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<JsonValue, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_unit<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<JsonValue, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<JsonValue, E> {
        self.number(value.into())
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<JsonValue, E> {
        self.number(value.into())
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<JsonValue, E> {
        let number =
            serde_json::Number::from_f64(value).ok_or_else(|| E::custom("non-finite number"))?;
        self.number(number)
    }

    fn visit_str<E>(self, value: &str) -> Result<JsonValue, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<JsonValue, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonValue, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(self)? {
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonValue, A::Error> {
        let mut entries: Vec<(String, JsonValue)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key {key:?}"
                )));
            }
            let value = map.next_value_seed(self)?;
            entries.push((key, value));
        }
        Ok(JsonValue::Object(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_key_order_round_trip() {
        let input = r#"{"z":1,"a":{"y":[1,2,{"b":null}],"c":true},"m":"x"}"#;
        let value = JsonValue::parse(input).unwrap();
        assert_eq!(value.to_compact(), input);
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        assert!(JsonValue::parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(JsonValue::parse(r#"{"p":{"name":"x","name":"y"}}"#).is_err());
    }

    #[test]
    fn rejects_trailing_data_and_deep_nesting() {
        assert!(JsonValue::parse(r#"{"a":1} {"b":2}"#).is_err());
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        assert!(JsonValue::parse(&deep).is_err());
    }

    #[test]
    fn set_keeps_position_or_inserts_after() {
        let mut value = JsonValue::parse(r#"{"command":"a","env":{}}"#).unwrap();
        value.set("args", JsonValue::Array(vec![]), Some("command"));
        value.set("command", JsonValue::string("b"), None);
        assert_eq!(value.to_compact(), r#"{"command":"b","args":[],"env":{}}"#);
        value.remove("args");
        assert_eq!(value.to_compact(), r#"{"command":"b","env":{}}"#);
    }

    fn number(text: &str) -> JsonNumber {
        match JsonValue::parse(text).unwrap() {
            JsonValue::Number(number) => number,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn numbers_keep_their_literal_in_document_order() {
        let input = r#"{"a-1":[1,-2.50,"3 \" 4e5",{"b":6E+1}],"c":0.1}"#;
        let value = JsonValue::parse(input).unwrap();
        // Serializing writes each literal back where it was read.
        assert_eq!(value.to_compact(), input);
        assert_eq!(number("-2.50").literal(), "-2.50");
        assert_eq!(number(" 7 ").literal(), "7");
    }

    #[test]
    fn floats_are_rounded_correctly() {
        // Without serde_json's `float_roundtrip` this reads 49.99999999999999.
        assert_eq!(number("49.9999999999999965").value().as_f64(), Some(50.0));
        assert_eq!(number("99.9999999999999929").value().as_f64(), Some(100.0));
    }

    #[test]
    fn only_a_literal_equal_to_its_serialized_value_is_canonical() {
        for text in [
            "0",
            "50",
            "-7",
            "50.0",
            "49.99999999999999",
            "0.1",
            "9007199254740993",
            "18446744073709551615",
        ] {
            assert!(number(text).is_canonical(), "{text}");
        }
        for text in [
            "49.9999999999999965",
            "99.9999999999999929",
            "50.00000000000000001",
            "50.00",
            "5e1",
            "1e2",
            "-0",
            "18446744073709551616",
            "0.1000000000000000055511151231257827",
        ] {
            assert!(!number(text).is_canonical(), "{text}");
        }
        assert!(JsonValue::parse("1e400").is_err());
    }
}
