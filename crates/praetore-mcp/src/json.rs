//! A small order-preserving JSON value that rejects duplicate object keys.
//!
//! Two uses:
//! * client configuration files, so `install`/`uninstall` keep the user's
//!   key order instead of re-sorting the whole document;
//! * classifying untrusted MCP traffic. Rejecting duplicate keys closes a
//!   parser differential: `{"method":"tools/list","method":"tools/call"}`
//!   could be read as `tools/list` here and as `tools/call` by the server.
//!
//! # Numbers
//!
//! [`JsonValue::Number`] keeps the original literal. The proxy evaluates a
//! parsed number and forwards the original bytes, so a literal is usable
//! only when every parser we accept produces that same value. The literal
//! is canonical when its text is exactly the canonical serialization below.
//! Anything else is ambiguous: enforce does not forward it.
//!
//! Canonical serialization, for a literal that is a JSON number token:
//!
//! * **Integers** (no `.` and no `e`/`E`). The canonical text is the decimal
//!   spelling of the value (`0`, `50`, `-3`): no leading zeros, `-` only when
//!   negative, so `-0` serializes as `0`. The absolute value must also be at
//!   most 2^53 (`9007199254740992`). `9007199254740993` (2^53+1) round-trips
//!   as an integer but is not exact in binary64, so an integer parser and a
//!   binary64 parser disagree. It is not canonical.
//! * **Fractions and exponents** (the token contains `.` or `e`/`E`). The
//!   literal is parsed with round-to-nearest-even binary64 (`serde_json`'s
//!   `float_roundtrip` feature) and serialized again with `serde_json`'s
//!   number formatting (shortest round trip). That text is the canonical
//!   form. Consequences:
//!   * trailing zeros are not canonical: `50.00` and `1.50` serialize as
//!     `50.0` and `1.5`;
//!   * an exponent spelling is canonical only when the formatter emits that
//!     same spelling. `1e2` serializes as `100.0`. Positive exponents that
//!     the formatter keeps use `e+`, so `1e308` serializes as `1e+308`;
//!   * a literal that is not a finite binary64 (`1e400`) is not canonical.
//! * A fraction whose extra digits do not survive the round trip is not
//!   canonical. `49.9999999999999965` serializes as `50.0`.
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

/// Largest integer that is exactly representable as binary64 (2^53).
pub const BINARY64_EXACT_INT_MAX: i128 = 1_i128 << 53;

/// One JSON number: the original token plus the finite value it parses to.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNumber {
    literal: String,
    /// `None` when the token is not a finite `serde_json` number (`1e400`).
    parsed: Option<serde_json::Number>,
}

impl JsonNumber {
    /// The number token, exactly as it appeared in the document.
    pub fn literal(&self) -> &str {
        &self.literal
    }

    /// Finite parsed value. Absent for a token such as `1e400`.
    pub fn parsed(&self) -> Option<&serde_json::Number> {
        self.parsed.as_ref()
    }

    /// Why this literal is not canonical, or `None` when it is.
    pub fn ambiguity(&self) -> Option<String> {
        number_literal_ambiguity(&self.literal)
    }

    fn from_parsed(number: serde_json::Number) -> Self {
        let literal = number.to_string();
        Self {
            literal,
            parsed: Some(number),
        }
    }

    fn from_literal(literal: String) -> Self {
        let parsed = parse_finite_number(&literal);
        Self { literal, parsed }
    }
}

impl Serialize for JsonNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.parsed {
            Some(number) => number.serialize(serializer),
            None => Err(serde::ser::Error::custom(format!(
                "non-finite number literal {}",
                self.literal
            ))),
        }
    }
}

/// Why `literal` cannot be evaluated and forwarded as the same value.
///
/// See the module docs for the canonical form of integers, exponents and
/// trailing zeros.
pub fn number_literal_ambiguity(literal: &str) -> Option<String> {
    if is_float_token(literal) {
        float_ambiguity(literal)
    } else {
        integer_ambiguity(literal)
    }
}

fn is_float_token(literal: &str) -> bool {
    literal
        .bytes()
        .any(|byte| matches!(byte, b'.' | b'e' | b'E'))
}

fn integer_ambiguity(literal: &str) -> Option<String> {
    let digits = literal.strip_prefix('-').unwrap_or(literal);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(format!(
            "number literal {literal} is not canonical; it is not a decimal integer"
        ));
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Some(format!(
            "number literal {literal} is not canonical; a correct parse serializes as {}",
            canonical_integer_or_range(literal)
        ));
    }
    // Longer than i128, or outside the binary64 exact range: no accepted form.
    let Ok(value) = literal.parse::<i128>() else {
        return Some(integer_range_reason(literal));
    };
    if value.abs() > BINARY64_EXACT_INT_MAX {
        return Some(integer_range_reason(literal));
    }
    let canonical = value.to_string();
    if literal != canonical {
        return Some(format!(
            "number literal {literal} is not canonical; a correct parse serializes as {canonical}"
        ));
    }
    None
}

fn canonical_integer_or_range(literal: &str) -> String {
    literal
        .parse::<i128>()
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "an integer inside the binary64 exact range".to_owned())
}

fn integer_range_reason(literal: &str) -> String {
    format!(
        "number literal {literal} is not canonical; its absolute value exceeds \
         {BINARY64_EXACT_INT_MAX} (2^53), so a binary64 parser and an integer parser disagree"
    )
}

fn float_ambiguity(literal: &str) -> Option<String> {
    let Some(number) = parse_finite_number(literal) else {
        return Some(format!(
            "number literal {literal} is not canonical; it is not a finite binary64 value"
        ));
    };
    let canonical = number.to_string();
    if canonical != literal {
        return Some(format!(
            "number literal {literal} is not canonical; a correct parse serializes as {canonical}"
        ));
    }
    None
}

fn parse_finite_number(literal: &str) -> Option<serde_json::Number> {
    let value: serde_json::Value = serde_json::from_str(literal).ok()?;
    let number = value.as_number()?.clone();
    if number.as_f64().is_some_and(|value| !value.is_finite()) {
        return None;
    }
    Some(number)
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
    /// trailing data. Number tokens are preserved; see [`JsonNumber`].
    pub fn parse(input: &str) -> Result<Self, String> {
        let (rewritten, literals) = split_number_literals(input)?;
        let mut deserializer = serde_json::Deserializer::from_str(&rewritten);
        let mut value = JsonValue::deserialize(&mut deserializer).map_err(|e| e.to_string())?;
        deserializer.end().map_err(|e| e.to_string())?;
        let mut literals = literals.into_iter();
        attach_literals(&mut value, &mut literals)?;
        if literals.next().is_some() {
            return Err("number literal count does not match the parsed document".into());
        }
        Ok(value)
    }

    /// The first number literal in this value that is not canonical.
    pub fn number_ambiguity(&self) -> Option<String> {
        match self {
            JsonValue::Number(number) => number.ambiguity(),
            JsonValue::Array(items) => items.iter().find_map(JsonValue::number_ambiguity),
            JsonValue::Object(entries) => entries
                .iter()
                .find_map(|(_, value)| value.number_ambiguity()),
            _ => None,
        }
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
    ///
    /// A finite number becomes its parsed value. A non-finite token becomes
    /// the literal text, so the token is not dropped.
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            JsonValue::Null => serde_json::Value::Null,
            JsonValue::Bool(value) => serde_json::Value::Bool(*value),
            JsonValue::Number(value) => match &value.parsed {
                Some(number) => serde_json::Value::Number(number.clone()),
                None => serde_json::Value::String(value.literal.clone()),
            },
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
        // Serializing this type cannot fail for finite numbers. A non-finite
        // token has no JSON number form; callers do not pretty-print those.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn to_compact(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

fn attach_literals(
    value: &mut JsonValue,
    literals: &mut impl Iterator<Item = String>,
) -> Result<(), String> {
    match value {
        JsonValue::Number(slot) => {
            let literal = literals
                .next()
                .ok_or("number literal count does not match the parsed document")?;
            *slot = JsonNumber::from_literal(literal);
            Ok(())
        }
        JsonValue::Array(items) => {
            for item in items {
                attach_literals(item, literals)?;
            }
            Ok(())
        }
        JsonValue::Object(entries) => {
            for (_, item) in entries {
                attach_literals(item, literals)?;
            }
            Ok(())
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::String(_) => Ok(()),
    }
}

/// Copies `input`, replacing every number token with `0`, and returns the
/// tokens in order. Strings are copied unchanged. Invalid number grammar is
/// an error. A token that is valid JSON but not a finite binary64 (`1e400`)
/// is kept so the caller can reject it as ambiguous instead of unparseable.
fn split_number_literals(input: &str) -> Result<(String, Vec<String>), String> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut rewritten = String::with_capacity(input.len());
    let mut literals = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let start = index;
                index = end_of_string(bytes, index)?;
                rewritten.push_str(&input[start..index]);
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                index = end_of_number(bytes, index)?;
                literals.push(input[start..index].to_owned());
                rewritten.push('0');
            }
            _ => {
                let ch = input[index..].chars().next().unwrap();
                rewritten.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Ok((rewritten, literals))
}

fn end_of_string(bytes: &[u8], mut index: usize) -> Result<usize, String> {
    index += 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    return Err("unterminated string".into());
                }
                index += 1;
            }
            b'"' => return Ok(index + 1),
            _ => index += 1,
        }
    }
    Err("unterminated string".into())
}

fn end_of_number(bytes: &[u8], mut index: usize) -> Result<usize, String> {
    if bytes[index] == b'-' {
        index += 1;
        if index >= bytes.len() || !bytes[index].is_ascii_digit() {
            return Err("invalid number".into());
        }
    }
    if bytes[index] == b'0' {
        index += 1;
    } else if bytes[index].is_ascii_digit() {
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
    } else {
        return Err("invalid number".into());
    }
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let fraction = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == fraction {
            return Err("invalid number".into());
        }
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        let exponent = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent {
            return Err("invalid number".into());
        }
    }
    Ok(index)
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
        Ok(JsonValue::Number(JsonNumber::from_parsed(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<JsonValue, E> {
        Ok(JsonValue::Number(JsonNumber::from_parsed(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<JsonValue, E> {
        serde_json::Number::from_f64(value)
            .map(JsonNumber::from_parsed)
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

    #[test]
    fn number_literal_is_stored_and_strings_are_not_numbers() {
        let value = JsonValue::parse(r#"{"amount":"49.9999999999999965","n":50}"#).unwrap();
        assert!(value.number_ambiguity().is_none(), "{value:?}");
        let JsonValue::Number(number) = value.get("n").unwrap() else {
            panic!("n is not a number");
        };
        assert_eq!(number.literal(), "50");
        assert_eq!(number.parsed().and_then(|n| n.as_i64()), Some(50));
    }

    #[test]
    fn canonical_integers_fractions_and_exponents() {
        for literal in [
            "0",
            "1",
            "50",
            "-3",
            "9007199254740992",
            "-9007199254740992",
            "0.0",
            "1.0",
            "1.5",
            "50.0",
            "-1.5",
            "0.5",
            "0.1",
            "100.0",
            "1e+308",
            "0.9999999999999999",
        ] {
            assert!(
                number_literal_ambiguity(literal).is_none(),
                "{literal} should be canonical: {:?}",
                number_literal_ambiguity(literal)
            );
        }
    }

    #[test]
    fn noncanonical_trailing_zeros_exponents_range_and_rounding() {
        let cases = [
            ("-0", "0"),
            ("50.00", "50.0"),
            ("1.50", "1.5"),
            ("1.2300", "1.23"),
            ("1e2", "100.0"),
            ("1E2", "100.0"),
            ("1e20", "1e+20"),
            ("1e308", "1e+308"),
            ("49.9999999999999965", "50.0"),
            ("99.9999999999999929", "100.0"),
            ("50.00000000000000001", "50.0"),
        ];
        for (literal, canonical) in cases {
            let reason = number_literal_ambiguity(literal).expect(literal);
            assert!(
                reason.contains(canonical),
                "{literal}: {reason} does not name {canonical}"
            );
            let value = JsonValue::parse(literal).unwrap();
            assert_eq!(value.number_ambiguity().as_deref(), Some(reason.as_str()));
        }
        for literal in ["9007199254740993", "-9007199254740993", "1e400"] {
            let reason = number_literal_ambiguity(literal).expect(literal);
            assert!(reason.contains("not canonical"), "{literal}: {reason}");
        }
    }

    #[test]
    fn boundary_float_parses_to_the_correct_binary64() {
        let value = JsonValue::parse("49.9999999999999965").unwrap();
        let JsonValue::Number(number) = value else {
            panic!("not a number");
        };
        assert_eq!(number.literal(), "49.9999999999999965");
        assert_eq!(number.parsed().and_then(|n| n.as_f64()), Some(50.0));
        assert!(number.ambiguity().is_some());
    }

    #[test]
    fn integer_past_the_mantissa_is_stored_exactly_and_rejected() {
        let value = JsonValue::parse("9007199254740993").unwrap();
        let JsonValue::Number(number) = value else {
            panic!("not a number");
        };
        assert_eq!(number.literal(), "9007199254740993");
        assert_eq!(
            number.parsed().and_then(|n| n.as_i64()),
            Some(9_007_199_254_740_993)
        );
        let reason = number.ambiguity().unwrap();
        assert!(reason.contains("2^53"), "{reason}");
    }

    #[test]
    fn overflow_literal_parses_as_a_document_and_is_not_finite() {
        let value = JsonValue::parse(r#"{"amount":1e400}"#).unwrap();
        let reason = value.number_ambiguity().unwrap();
        assert!(reason.contains("1e400"), "{reason}");
        assert!(reason.contains("not a finite binary64"), "{reason}");
        assert!(matches!(
            value.get("amount").unwrap().to_value(),
            serde_json::Value::String(text) if text == "1e400"
        ));
    }
}
