//! The page's catalogs (`ui/i18n/{es,en,pt}.json`) and the codes the
//! console sends: every code has its words in every language, with the same
//! parameters, and nothing the console signs, records or exports reads a
//! catalog or a language.

use crate::codigos::{
    ApiMessage, MessageCode, Notice, OutcomeState, Placeholder, Situation, Story,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const LANGUAGES: [&str; 3] = ["es", "en", "pt"];

fn catalog_text(language: &str) -> &'static str {
    crate::CATALOGS
        .iter()
        .find(|(code, _)| *code == language)
        .map(|(_, text)| *text)
        .unwrap()
}

/// One catalog: key to value, a value being a text or plural forms.
fn catalog(language: &str) -> BTreeMap<String, Value> {
    serde_json::from_str(catalog_text(language)).unwrap()
}

/// Every text of a catalog, one entry per text: `key` for a text and
/// `key#form` for each plural form.
fn texts(language: &str) -> BTreeMap<String, String> {
    let mut flat = BTreeMap::new();
    for (key, value) in catalog(language) {
        match value {
            Value::String(text) => {
                flat.insert(key, text);
            }
            Value::Object(forms) => {
                for (form, text) in forms {
                    flat.insert(format!("{key}#{form}"), text.as_str().unwrap().to_owned());
                }
            }
            other => panic!("{language}: {key} is {other}"),
        }
    }
    flat
}

/// The Spanish words of `key` (the `other` form of a plural).
pub(crate) fn es(key: &str) -> String {
    match catalog("es").remove(key) {
        Some(Value::String(text)) => text,
        Some(Value::Object(forms)) => forms["other"].as_str().unwrap().to_owned(),
        _ => panic!("es.json has no {key}"),
    }
}

/// The Spanish words of a message, with its parameters filled in.
pub(crate) fn es_message(message: &ApiMessage) -> String {
    es_json_message(&serde_json::to_value(message).unwrap())
}

/// Same, from the JSON the page receives (`{"codigo": ..., ...}`).
pub(crate) fn es_json_message(message: &Value) -> String {
    let mut text = es(&format!("message.{}", message["codigo"].as_str().unwrap()));
    for (name, value) in message.as_object().unwrap() {
        if name != "codigo" {
            text = text.replace(&format!("{{{name}}}"), &value.to_string());
        }
    }
    text
}

/// `{name}` markers of a text.
fn markers(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        found.insert(rest[start + 1..start + end].to_owned());
        rest = &rest[start + end + 1..];
    }
    found
}

#[test]
fn the_three_catalogs_have_the_same_keys_and_no_empty_text() {
    let spanish: BTreeSet<String> = texts("es").into_keys().collect();
    assert!(spanish.len() > 100, "{}", spanish.len());
    for language in LANGUAGES {
        let flat = texts(language);
        let keys: BTreeSet<String> = flat.keys().cloned().collect();
        let missing: Vec<_> = spanish.difference(&keys).collect();
        let extra: Vec<_> = keys.difference(&spanish).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{language}.json: missing {missing:?}, not in es.json {extra:?}"
        );
        for (key, text) in &flat {
            assert!(!text.trim().is_empty(), "{language}.json: {key} is empty");
        }
        // A plural has at least the forms every language needs.
        for (key, value) in catalog(language) {
            if let Value::Object(forms) = value {
                assert!(
                    forms.contains_key("one") && forms.contains_key("other"),
                    "{language}.json: {key} needs one and other"
                );
            }
        }
    }
}

#[test]
fn every_text_has_the_same_markers_in_every_language() {
    let spanish = texts("es");
    for language in LANGUAGES {
        for (key, text) in texts(language) {
            assert_eq!(
                markers(&text),
                markers(&spanish[&key]),
                "{language}.json: {key}"
            );
        }
    }
}

/// Every code the server can send, walked from the Rust enums.
fn server_keys() -> BTreeMap<String, BTreeSet<String>> {
    let mut keys = BTreeMap::new();
    let none = BTreeSet::new;
    for situation in Situation::ALL {
        keys.insert(format!("situation.{}", situation.code()), none());
    }
    for state in OutcomeState::ALL {
        keys.insert(format!("situation.{}", state.code()), none());
    }
    for story in Story::ALL {
        keys.insert(format!("story.{}", story.code()), none());
    }
    for notice in Notice::ALL {
        keys.insert(format!("notice.{}", notice.code()), none());
    }
    for placeholder in Placeholder::ALL {
        keys.insert(format!("value.{}", placeholder.code()), none());
    }
    for message in MessageCode::ALL {
        keys.insert(
            format!("message.{}", message.code()),
            message
                .params()
                .iter()
                .map(|param| (*param).to_owned())
                .collect(),
        );
    }
    keys
}

#[test]
fn every_code_the_server_sends_has_its_words_and_parameters() {
    let keys = server_keys();
    assert!(keys.len() > 90, "{}", keys.len());
    for language in LANGUAGES {
        let catalog = catalog(language);
        for (key, params) in &keys {
            let Some(Value::String(text)) = catalog.get(key) else {
                panic!("{language}.json has no text for {key}");
            };
            assert_eq!(&markers(text), params, "{language}.json: {key}");
        }
    }
}

#[test]
fn message_codes_are_unique_and_snake_case() {
    let mut seen = BTreeSet::new();
    for message in MessageCode::ALL {
        let code = message.code();
        assert!(seen.insert(code), "{code} twice");
        assert!(
            code.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{code}"
        );
        assert_eq!(MessageCode::from_code(code), Some(*message));
    }
}

/// `t("key")` literals of a script, and the prefixes of `t("prefix." + ...)`.
fn script_keys(script: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let (mut literal, mut prefixes) = (BTreeSet::new(), BTreeSet::new());
    for (index, _) in script.match_indices("t(\"") {
        // Only the translator: `t(` not preceded by an identifier character.
        let before = script[..index].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
            continue;
        }
        let rest = &script[index + 3..];
        let end = rest.find('"').unwrap();
        let key = &rest[..end];
        if rest[end + 1..].trim_start().starts_with('+') {
            prefixes.insert(key.to_owned());
        } else {
            literal.insert(key.to_owned());
        }
    }
    (literal, prefixes)
}

/// Keys written as plain strings where a key is expected: `boton("...")`,
/// `confirmar("...", "...")`, `{ clave: "..." }` and the fallback of
/// `mensaje(..., "...")`.
fn other_literal_keys(script: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let known = ["situation.", "story.", "notice.", "message.", "value."];
    let families = [
        "button.",
        "confirm.",
        "time_left.",
        "inbox.",
        "history.",
        "pack.",
        "params.",
        "field.",
        "agent.",
        "session.",
    ];
    for piece in script.split('"').skip(1).step_by(2) {
        let is_key = piece.contains('.')
            && !piece.contains(' ')
            && !piece.contains('/')
            && (families
                .iter()
                .chain(known.iter())
                .any(|family| piece.starts_with(family)))
            && piece.len() > piece.find('.').unwrap() + 1;
        if is_key {
            keys.insert(piece.to_owned());
        }
    }
    keys
}

#[test]
fn every_key_the_page_uses_is_in_every_catalog() {
    let scripts = [
        ("app.js", include_str!("../ui/app.js")),
        ("hora.js", include_str!("../ui/hora.js")),
        ("i18n.js", include_str!("../ui/i18n.js")),
    ];
    let mut used = BTreeSet::new();
    for (name, script) in scripts {
        let (literal, prefixes) = script_keys(script);
        used.extend(literal);
        used.extend(other_literal_keys(script));
        // Keys built from a code: only the families the server's codes fill
        // (checked in `every_code_the_server_sends_has_its_words_and_parameters`).
        for prefix in prefixes {
            assert!(
                ["situation.", "story.", "notice.", "message.", "value."]
                    .contains(&prefix.as_str()),
                "{name}: t(\"{prefix}\" + ...) is not a family of server codes"
            );
        }
    }
    let page = include_str!("../ui/index.html");
    let mut in_page = 0;
    for piece in page.split("data-i18n=\"").skip(1) {
        used.insert(piece[..piece.find('"').unwrap()].to_owned());
        in_page += 1;
    }
    assert!(in_page >= 20, "{in_page}");
    assert!(used.contains("confirm.reject.question"));
    assert!(used.contains("time_left.minutes"));
    for language in LANGUAGES {
        let catalog = catalog(language);
        for key in &used {
            assert!(catalog.contains_key(key), "{language}.json has no {key}");
        }
    }
}

#[test]
fn the_reject_confirmation_says_it_is_final_in_every_language() {
    for (language, word) in [("es", "es final"), ("en", "final"), ("pt", "final")] {
        let question = catalog(language)["confirm.reject.question"]
            .as_str()
            .unwrap()
            .to_lowercase();
        assert!(question.contains(word), "{language}: {question}");
    }
    // The approve and reject confirmations are not the same words.
    for language in LANGUAGES {
        let catalog = catalog(language);
        assert_ne!(
            catalog["confirm.reject.question"],
            catalog["confirm.approve_execute.question"]
        );
        assert_ne!(
            catalog["confirm.reject.button"],
            catalog["confirm.approve_execute.button"]
        );
    }
}

/// A capital letter, an optional hyphen and digits, standing alone (as in
/// "Q-7" or "Z9"): the shape of an internal label.
fn has_internal_label(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    for start in 0..chars.len() {
        if !chars[start].is_ascii_uppercase() || (start > 0 && chars[start - 1].is_alphanumeric()) {
            continue;
        }
        let mut index = start + 1;
        if chars.get(index) == Some(&'-') {
            index += 1;
        }
        let digits = index;
        while chars.get(index).is_some_and(char::is_ascii_digit) {
            index += 1;
        }
        let after = chars.get(index);
        if index > digits && !after.is_some_and(|c| c.is_alphanumeric()) {
            return Some(chars[start..index].iter().collect());
        }
    }
    None
}

#[test]
fn the_catalogs_hold_no_forbidden_public_terms() {
    let forbidden = [
        "autonomous",
        "autónomo",
        "autônomo",
        "production",
        "producción",
        "produção",
        "bypass",
        "macos",
    ];
    for language in LANGUAGES {
        for (key, text) in texts(language) {
            let lower = text.to_lowercase();
            for term in forbidden {
                assert!(!lower.contains(term), "{language}.json: {key} says {term}");
            }
            assert_eq!(
                has_internal_label(&text),
                None,
                "{language}.json: {key}: {text}"
            );
        }
    }
    assert_eq!(has_internal_label("see Q-7 here"), Some("Q-7".into()));
    assert_eq!(has_internal_label("Z9"), Some("Z9".into()));
    assert_eq!(has_internal_label("SHA-256 and UTC+05:30"), None);
}

/// Presentation only: the modules that sign, record or export never read a
/// catalog or a language. A change that makes them (a translated LEEME, a
/// signature over a localized text) fails here.
#[test]
fn signing_recording_and_exporting_do_not_depend_on_the_language() {
    let sources = [
        ("aprobador.rs", include_str!("aprobador.rs")),
        ("paquete.rs", include_str!("paquete.rs")),
        ("confianza.rs", include_str!("confianza.rs")),
        (
            "praetore-replay-postgres journal_export.rs",
            include_str!("../../praetore-replay-postgres/src/journal_export.rs"),
        ),
        (
            "praetore-receipt outcomes.rs",
            include_str!("../../praetore-receipt/src/outcomes.rs"),
        ),
    ];
    let forbidden = [
        "i18n",
        "catálogo",
        "catalogo",
        "catalogs",
        "accept-language",
        "accept_language",
        "idioma",
        "praetore_idioma",
        "es.json",
        "en.json",
        "pt.json",
        "tests_i18n",
        "locale",
    ];
    for (name, source) in sources {
        let lower = source.to_lowercase();
        for term in forbidden {
            assert!(!lower.contains(term), "{name} mentions {term}");
        }
    }
}
