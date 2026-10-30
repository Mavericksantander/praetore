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

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Parses one complete JSON document, rejecting duplicate keys and
    /// trailing data.
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut deserializer = serde_json::Deserializer::from_str(input);
        let value = JsonValue::deserialize(&mut deserializer).map_err(|e| e.to_string())?;
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
            JsonValue::Number(value) => serde_json::Value::Number(value.clone()),
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
        // Serializing this type cannot fail: keys are strings and numbers are
        // already valid `serde_json::Number`s.
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
            JsonValue::Number(value) => value.serialize(serializer),
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

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonValueVisitor)
    }
}

struct JsonValueVisitor;

impl<'de> Visitor<'de> for JsonValueVisitor {
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

    fn visit_i64<E>(self, value: i64) -> Result<JsonValue, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<JsonValue, E> {
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<JsonValue, E> {
        serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<JsonValue, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<JsonValue, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonValue, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<JsonValue>()? {
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
            let value = map.next_value::<JsonValue>()?;
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
}
