//! D2: the approvals inbox.
//!
//! Which requests wait for a person, said in plain words: who, what, on what,
//! and until when. The browser never receives the journal keys: each pending
//! request gets an opaque reference that only this process can resolve.

use crate::historia::{quoted_text, readable_time};
use praetore_core::Evidence;
use praetore_gateway::{ApprovalChallenge, ExecutionKey, action_digest};
use std::{collections::HashMap, sync::Mutex};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use unicode_normalization::{UnicodeNormalization, is_nfc};
use uuid::Uuid;

/// How many pending requests one inbox read returns, newest first.
pub const INBOX_LIMIT: u32 = 200;
/// Opaque references kept in memory before the table is reset.
const MAX_REFERENCES: usize = 4096;
const REFERENCE_ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz23456789_";
const REFERENCE_LEN: usize = 20;

/// What a pending request still needs from the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// Nobody has decided yet: approve or reject.
    AwaitingApproval,
    /// Approved, and the single execution has not happened yet.
    ApprovedPendingExecution,
}

impl PendingKind {
    pub fn phrase(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "pendiente de aprobación",
            Self::ApprovedPendingExecution => "aprobado, pendiente de ejecución",
        }
    }
}

/// One journal row that waits for the operator, reduced to what the console
/// may say plus what it needs to check the gateway challenge before signing.
#[derive(Debug, Clone)]
pub struct PendingFacts {
    pub created_at: OffsetDateTime,
    pub key: ExecutionKey,
    pub kind: PendingKind,
    pub wanted: String,
    pub target: Option<String>,
    /// Digest of the action read from the journal evidence (hash checked,
    /// attester signature not checked). The challenge the gateway hands
    /// back must commit to this same digest.
    pub action_digest: String,
    /// The challenge the gateway must hand back, rebuilt from the evidence
    /// exactly as the gateway builds it.
    pub expected: ApprovalChallenge,
    pub expires_at: OffsetDateTime,
    /// The action parameters, keys sorted, or `None` when they cannot be
    /// shown within the inbox limits without ambiguity. The signature covers
    /// them, so a request whose parameters cannot be shown cannot be
    /// approved here.
    pub parameters: Option<Vec<Parameter>>,
}

/// One shown parameter: `clave` and a text or a list of texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    pub key: String,
    pub value: ParameterValue,
}

/// Strings are quoted and escaped, numbers are shown as written, so `"10"`
/// and `10` (or `"sí"` and `sí`) are told apart. A list keeps each
/// element apart, so a string with a comma is never two elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterValue {
    Text(String),
    List(Vec<String>),
}

/// Inbox limits for shown parameters. Each list element counts as a line.
pub const MAX_PARAMETER_LINES: usize = 20;
pub const MAX_PARAMETER_CHARS: usize = 200;
pub const MAX_PARAMETER_DEPTH: usize = 2;

/// The action parameters, keys sorted. Keys are quoted like texts, so a
/// trailing space shows; nested objects as `"clave"."subclave"`.
/// `None` (only rejecting is offered) when they do not fit or could be
/// read two ways: more than 20 lines, a key or value longer than 200
/// characters once escaped, nesting deeper than 2, a non-object root, an
/// empty key, a key with a dot, a key or text not in Unicode NFC (`é` and
/// `e` + U+0301 look the same), or two keys that repeat once normalized
/// (NFKC, lower case).
pub fn parameters_shown(parameters: &serde_json::Value) -> Option<Vec<Parameter>> {
    let serde_json::Value::Object(map) = parameters else {
        return None;
    };
    let mut shown = Vec::new();
    let mut lines = 0;
    collect(map, "", 1, &mut shown, &mut lines)?;
    shown.sort_by(|left, right| left.key.cmp(&right.key));
    let mut normalized: Vec<String> = shown
        .iter()
        .map(|item| item.key.nfkc().collect::<String>().to_lowercase())
        .collect();
    normalized.sort();
    let unique = normalized.windows(2).all(|pair| pair[0] != pair[1]);
    unique.then_some(shown)
}

fn collect(
    map: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    depth: usize,
    shown: &mut Vec<Parameter>,
    lines: &mut usize,
) -> Option<()> {
    use serde_json::Value;
    for (key, value) in map {
        if key.is_empty() || key.contains('.') || !is_nfc(key) {
            return None;
        }
        let key = format!("{prefix}{}", quoted_text(key));
        if key.chars().count() > MAX_PARAMETER_CHARS {
            return None;
        }
        let value = match value {
            Value::Object(inner) if inner.is_empty() => {
                if depth >= MAX_PARAMETER_DEPTH {
                    return None;
                }
                ParameterValue::Text("(objeto vacío)".to_owned())
            }
            Value::Object(inner) => {
                if depth >= MAX_PARAMETER_DEPTH {
                    return None;
                }
                collect(inner, &format!("{key}."), depth + 1, shown, lines)?;
                continue;
            }
            Value::Array(items) => {
                // Elements must be scalars: an array is one level.
                let mut parts = Vec::with_capacity(items.len());
                for item in items {
                    parts.push(scalar_text(item)?);
                    *lines += 1;
                }
                if parts.is_empty() {
                    *lines += 1;
                }
                ParameterValue::List(parts)
            }
            scalar => {
                *lines += 1;
                ParameterValue::Text(scalar_text(scalar)?)
            }
        };
        if *lines > MAX_PARAMETER_LINES {
            return None;
        }
        shown.push(Parameter { key, value });
    }
    Some(())
}

fn scalar_text(value: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    let text = match value {
        Value::String(text) if !is_nfc(text) => return None,
        Value::String(text) => quoted_text(text),
        Value::Number(number) => number.to_string(),
        Value::Bool(true) => "sí".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::Null => "(nulo)".to_owned(),
        Value::Array(_) | Value::Object(_) => return None,
    };
    (text.chars().count() <= MAX_PARAMETER_CHARS).then_some(text)
}

/// Journal columns the inbox reads. Evidence JSON is consumed here.
pub struct PendingColumns {
    pub created_at: OffsetDateTime,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub kind: PendingKind,
    pub evidence_json: String,
}

/// Fails closed on any receipt that does not verify, belongs to another
/// tenant or key, or has no approval window.
pub fn pending_from_columns(tenant_id: Uuid, columns: PendingColumns) -> Result<PendingFacts, ()> {
    let evidence = Evidence::from_json(&columns.evidence_json).map_err(|_| ())?;
    if !evidence.verify_integrity() {
        return Err(());
    }
    let digest = action_digest(&evidence.action).map_err(|_| ())?;
    let challenge = ApprovalChallenge::from_evidence(&evidence, &digest).map_err(|_| ())?;
    if challenge.tenant_id != tenant_id
        || challenge.agent_id != columns.agent_id
        || challenge.request_id != columns.request_id
    {
        return Err(());
    }
    let expires_at = OffsetDateTime::parse(&challenge.expires_at, &Rfc3339).map_err(|_| ())?;
    let challenge = challenge.clone();
    let parameters = parameters_shown(&evidence.action.parameters);
    let target = evidence.action.target.filter(|target| !target.is_empty());
    Ok(PendingFacts {
        created_at: columns.created_at,
        key: ExecutionKey {
            tenant_id,
            agent_id: columns.agent_id,
            request_id: columns.request_id,
        },
        kind: columns.kind,
        wanted: evidence.action.action_type,
        target,
        action_digest: digest,
        expected: challenge,
        expires_at,
        parameters,
    })
}

/// Expiry with seconds: windows can be short.
pub fn readable_deadline(moment: OffsetDateTime) -> String {
    let moment = moment.to_offset(time::UtcOffset::UTC);
    let minutes = readable_time(moment);
    // "12 de noviembre de 2026, 15:04 UTC" -> "..., 15:04:09 UTC"
    match minutes.strip_suffix(" UTC") {
        Some(base) => format!("{base}:{:02} UTC", moment.second()),
        None => minutes,
    }
}

/// Plain words for the time left, from the console's clock. Informational:
/// the gateway decides with its trusted clock.
pub fn time_left(expires_at: OffsetDateTime, now: OffsetDateTime) -> String {
    let left = expires_at - now;
    let seconds = left.whole_seconds();
    if seconds <= 0 {
        "la ventana ya cerró".to_owned()
    } else if seconds < 60 {
        "quedan menos de un minuto".to_owned()
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        if minutes == 1 {
            "queda 1 minuto".to_owned()
        } else {
            format!("quedan {minutes} minutos")
        }
    } else {
        let hours = seconds / 3600;
        if hours == 1 {
            "queda más de 1 hora".to_owned()
        } else {
            format!("quedan más de {hours} horas")
        }
    }
}

/// What a reference resolves to. Only this process knows the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRef {
    pub key: ExecutionKey,
    pub action_digest: String,
    pub expected: ApprovalChallenge,
    /// False when the parameters could not be shown: approving is refused
    /// server side, rejecting is not.
    pub approvable: bool,
}

impl From<&PendingFacts> for PendingRef {
    fn from(facts: &PendingFacts) -> Self {
        Self {
            key: facts.key,
            action_digest: facts.action_digest.clone(),
            expected: facts.expected.clone(),
            approvable: facts.parameters.is_some(),
        }
    }
}

/// Opaque references for pending requests. A reference is random, stable
/// for the same request while this process runs, and meaningless after a
/// restart (an old page then gets "ya no está").
#[derive(Default)]
pub struct References {
    inner: Mutex<ReferenceTable>,
}

#[derive(Default)]
struct ReferenceTable {
    by_reference: HashMap<String, PendingRef>,
    by_key: HashMap<(Uuid, Uuid), String>,
}

impl References {
    pub fn reference_for(&self, facts: &PendingFacts) -> Option<String> {
        let mut table = self.inner.lock().ok()?;
        let key = (facts.key.agent_id, facts.key.request_id);
        if let Some(existing) = table.by_key.get(&key).cloned()
            && let Some(known) = table.by_reference.get(&existing)
        {
            if known.action_digest == facts.action_digest
                && known.key == facts.key
                && known.expected == facts.expected
                && known.approvable == facts.parameters.is_some()
            {
                return Some(existing);
            }
            // Same journal key, different action: never reuse the reference.
            table.by_reference.remove(&existing);
            table.by_key.remove(&key);
        }
        if table.by_reference.len() >= MAX_REFERENCES {
            table.by_reference.clear();
            table.by_key.clear();
        }
        let reference = loop {
            let candidate = new_reference()?;
            if !table.by_reference.contains_key(&candidate) {
                break candidate;
            }
        };
        table
            .by_reference
            .insert(reference.clone(), PendingRef::from(facts));
        table.by_key.insert(key, reference.clone());
        Some(reference)
    }

    pub fn resolve(&self, reference: &str) -> Option<PendingRef> {
        if !valid_reference(reference) {
            return None;
        }
        self.inner.lock().ok()?.by_reference.get(reference).cloned()
    }
}

pub fn valid_reference(reference: &str) -> bool {
    reference.len() == REFERENCE_LEN
        && reference
            .bytes()
            .all(|byte| REFERENCE_ALPHABET.contains(&byte))
}

/// A random code from the reference alphabet: not hex, not a UUID.
pub fn random_code() -> Option<String> {
    new_reference()
}

fn new_reference() -> Option<String> {
    let bytes = crate::sesion::random_bytes().ok()?;
    Some(
        bytes[..REFERENCE_LEN]
            .iter()
            .map(|byte| char::from(REFERENCE_ALPHABET[usize::from(byte & 31)]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn facts(request: u128, digest: &str) -> PendingFacts {
        PendingFacts {
            created_at: datetime!(2026-11-12 10:00 UTC),
            key: ExecutionKey {
                tenant_id: Uuid::from_u128(1),
                agent_id: Uuid::from_u128(2),
                request_id: Uuid::from_u128(request),
            },
            kind: PendingKind::AwaitingApproval,
            wanted: "borrar_archivo".into(),
            target: Some("informe".into()),
            action_digest: digest.into(),
            expected: ApprovalChallenge {
                schema_version: 1,
                tenant_id: Uuid::from_u128(1),
                agent_id: Uuid::from_u128(2),
                request_id: Uuid::from_u128(request),
                evidence_id: Uuid::from_u128(request),
                evidence_hash: String::new(),
                action_digest: digest.into(),
                policy_digest: String::new(),
                expires_at: String::new(),
            },
            expires_at: datetime!(2026-11-12 10:05:09 UTC),
            parameters: Some(Vec::new()),
        }
    }

    #[test]
    fn references_are_opaque_stable_and_bound_to_the_action() {
        let references = References::default();
        let first = references.reference_for(&facts(3, "aa")).unwrap();
        assert!(valid_reference(&first));
        assert!(Uuid::parse_str(&first).is_err());
        assert!(!first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(references.reference_for(&facts(3, "aa")).unwrap(), first);
        let other = references.reference_for(&facts(4, "aa")).unwrap();
        assert_ne!(other, first);
        let resolved = references.resolve(&first).unwrap();
        assert_eq!(resolved.key.request_id, Uuid::from_u128(3));
        assert_eq!(resolved.action_digest, "aa");

        // A different action under the same key gets a new reference and the
        // old one stops resolving.
        let changed = references.reference_for(&facts(3, "bb")).unwrap();
        assert_ne!(changed, first);
        assert!(references.resolve(&first).is_none());
        assert_eq!(references.resolve(&changed).unwrap().action_digest, "bb");

        assert!(references.resolve("no-es-una-referencia").is_none());
        assert!(references.resolve(&"a".repeat(REFERENCE_LEN)).is_none());
    }

    #[test]
    fn parameters_are_sorted_quoted_and_kept_apart_within_fixed_limits() {
        use serde_json::json;
        let text = |value: &str| ParameterValue::Text(value.to_owned());
        let shown = parameters_shown(&json!({
            "monto": 100000,
            "cuenta": "cuenta-1",
            "opciones": {"urgente": true, "nota": null},
            "etiquetas": ["a", "b"],
            "texto": "x\u{202e}y",
        }))
        .unwrap();
        let keys: Vec<&str> = shown.iter().map(|item| item.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "\"cuenta\"",
                "\"etiquetas\"",
                "\"monto\"",
                "\"opciones\".\"nota\"",
                "\"opciones\".\"urgente\"",
                "\"texto\""
            ]
        );
        assert_eq!(shown[0].value, text("\"cuenta-1\""));
        assert_eq!(
            shown[1].value,
            ParameterValue::List(vec!["\"a\"".into(), "\"b\"".into()])
        );
        assert_eq!(shown[2].value, text("100000"));
        assert_eq!(shown[3].value, text("(nulo)"));
        assert_eq!(shown[4].value, text("sí"));
        assert_eq!(shown[5].value, text("\"x\\u{202e}y\""));
        assert_eq!(parameters_shown(&json!({})).unwrap(), Vec::new());

        // Too many lines, too long, too deep, or not an object: not shown.
        let many: serde_json::Map<_, _> = (0..=MAX_PARAMETER_LINES)
            .map(|index| (format!("k{index:02}"), json!(index)))
            .collect();
        assert!(parameters_shown(&serde_json::Value::Object(many)).is_none());
        let exactly: serde_json::Map<_, _> = (0..MAX_PARAMETER_LINES)
            .map(|index| (format!("k{index:02}"), json!(index)))
            .collect();
        assert!(parameters_shown(&serde_json::Value::Object(exactly)).is_some());
        let long_list: Vec<u32> = (0..=MAX_PARAMETER_LINES as u32).collect();
        assert!(parameters_shown(&json!({ "l": long_list })).is_none());
        // 198 characters plus the two quotes is the most a text can be.
        assert!(parameters_shown(&json!({"v": "x".repeat(MAX_PARAMETER_CHARS - 2)})).is_some());
        assert!(parameters_shown(&json!({"v": "x".repeat(MAX_PARAMETER_CHARS - 1)})).is_none());
        // Escaping counts: 40 bidi characters become 320 visible ones.
        assert!(parameters_shown(&json!({"v": "\u{202e}".repeat(40)})).is_none());
        assert!(parameters_shown(&json!({"a": {"b": {"c": 1}}})).is_none());
        assert!(parameters_shown(&json!({"a": [[1]]})).is_none());
        assert!(parameters_shown(&json!({"a": [{"b": 1}]})).is_none());
        assert!(parameters_shown(&json!("texto")).is_none());
        assert!(parameters_shown(&json!([1, 2])).is_none());
    }

    #[test]
    fn signed_parameters_that_differ_never_look_the_same() {
        use serde_json::json;
        let pairs = [
            (json!({"monto": "10"}), json!({"monto": 10})),
            (json!({"ok": "sí"}), json!({"ok": true})),
            (json!({"ok": "no"}), json!({"ok": false})),
            (json!({"v": "(nulo)"}), json!({"v": null})),
            (json!({"l": ["a, b"]}), json!({"l": ["a", "b"]})),
            (json!({"l": "a"}), json!({"l": ["a"]})),
            (json!({"l": "\"a\", \"b\""}), json!({"l": ["a", "b"]})),
            (json!({"v": "a\"b"}), json!({"v": "a\\\"b"})),
            (json!({"v": "\\u{202e}"}), json!({"v": "\u{202e}"})),
            (json!({"v": "ab"}), json!({"v": "a\u{200b}b"})),
            (json!({"v": "ab"}), json!({"v": "a\u{feff}b"})),
            (json!({"v": "ab"}), json!({"v": "a\u{2060}b"})),
            (json!({"v": "ab"}), json!({"v": "a\u{00ad}b"})),
            (json!({"v": "a b"}), json!({"v": "a\u{2028}b"})),
            (json!({"v": "a b"}), json!({"v": "a\u{2029}b"})),
            (json!({"clave": 1}), json!({"cla\u{200b}ve": 1})),
            (json!({"v": {}}), json!({"v": "(objeto vacío)"})),
        ];
        for (left, right) in pairs {
            let left_shown = parameters_shown(&left);
            let right_shown = parameters_shown(&right);
            assert!(
                left_shown.is_none() || right_shown.is_none() || left_shown != right_shown,
                "{left} and {right} look the same"
            );
        }
        // Escaped by Unicode category, not by a closed list.
        for hidden in [
            '\u{200d}',  // zero-width joiner (Cf)
            '\u{00a0}',  // no-break space (Zs)
            '\u{3000}',  // ideographic space (Zs)
            '\u{e0041}', // tag latin capital A (Cf)
            '\u{fe0f}',  // variation selector 16
            '\u{034f}',  // combining grapheme joiner
            '\u{3164}',  // hangul filler
            '\u{2800}',  // blank braille pattern
            '\u{e000}',  // private use (Co)
            '\u{0378}',  // unassigned (Cn)
        ] {
            let with = parameters_shown(&json!({ "v": format!("a{hidden}b") })).unwrap();
            let without = parameters_shown(&json!({"v": "ab"})).unwrap();
            assert_ne!(with, without, "U+{:04X}", hidden as u32);
            assert_eq!(
                with[0].value,
                ParameterValue::Text(format!("\"a\\u{{{:04x}}}b\"", hidden as u32))
            );
        }
        // Plain spaces, letters and emoji stay as they are.
        assert_eq!(
            parameters_shown(&json!({"v": "a b é ✓"})).unwrap()[0].value,
            ParameterValue::Text("\"a b é ✓\"".to_owned())
        );
        // Keys are quoted: a trailing space shows.
        let spaced = parameters_shown(&json!({"monto ": 1})).unwrap();
        assert_eq!(spaced[0].key, "\"monto \"");
        assert_ne!(spaced, parameters_shown(&json!({"monto": 1})).unwrap());
        // A key with a dot could be read as a nested key: only rejecting.
        assert!(parameters_shown(&json!({"a.b": 1})).is_none());
        assert!(parameters_shown(&json!({"a": {"b": 1}})).is_some());
        assert!(parameters_shown(&json!({"": 1})).is_none());
        // Escaping is one to one, so escaped keys never collide.
        assert!(parameters_shown(&json!({"\\u{200b}": 1, "\u{200b}": 1})).is_some());
        // Keys that repeat once normalized (NFKC, lower case): only rejecting.
        assert!(parameters_shown(&json!({"monto": 1, "Monto": 2})).is_none());
        assert!(parameters_shown(&json!({"monto": 1, "\u{ff4d}onto": 2})).is_none());
        assert!(parameters_shown(&json!({"a": {"x": 1}, "A": {"x": 2}})).is_none());
        // Not NFC (looks like an NFC text): only rejecting.
        assert!(parameters_shown(&json!({"v": "caf\u{e9}"})).is_some());
        assert!(parameters_shown(&json!({"v": "cafe\u{301}"})).is_none());
        assert!(parameters_shown(&json!({"cafe\u{301}": 1})).is_none());
    }

    #[test]
    fn deadlines_are_words_with_seconds() {
        assert_eq!(
            readable_deadline(datetime!(2026-11-12 10:05:09 UTC)),
            "12 de noviembre de 2026, 10:05:09 UTC"
        );
        let now = datetime!(2026-11-12 10:00 UTC);
        assert_eq!(
            time_left(datetime!(2026-11-12 10:00:30 UTC), now),
            "quedan menos de un minuto"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 10:05:09 UTC), now),
            "quedan 5 minutos"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 13:00 UTC), now),
            "quedan más de 3 horas"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 09:00 UTC), now),
            "la ventana ya cerró"
        );
    }
}
