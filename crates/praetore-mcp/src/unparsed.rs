//! The signed receipt of a client line this proxy cannot parse (T-016-B4).
//!
//! Every `Unparseable` line gets one receipt of action type
//! [`UNPARSED_LINE_ACTION_TYPE`], in both modes, written before the line is
//! forwarded (observe) or refused with `-32700` (enforce, and in both modes
//! a line that may name a `safety*` tool, signed `may_name_safety: true`).
//! No policy may declare that type ([`refuse_reserved_type`]), so the
//! engine refuses it with its unclassified-action guard: the receipt is a signed DENY and never says
//! "allow". What happens to the line depends on the mode and on
//! `may_name_safety_tool` only; nothing in this record decides it, and a
//! receipt that cannot be written changes nothing but the notice.

use crate::gate::Mode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Action type of the receipt of an unparseable client line. Reserved: a
/// policy that declares it in `action_classes` is refused by `policy check`,
/// by loading the home (`wrap`, `Gate::load`) and by the `policy` edits
/// ([`refuse_reserved_type`]).
pub const UNPARSED_LINE_ACTION_TYPE: &str = "mcp.unparsed_line";

/// Refuses a policy that declares [`UNPARSED_LINE_ACTION_TYPE`]. Declared,
/// the engine would not treat it as unclassified and every unparseable line
/// would lose its receipt. (As Safety the core already refuses it: a Safety
/// type is `safety:` followed by a name.)
pub fn refuse_reserved_type(policy: &praetore_core::Policy) -> Result<(), String> {
    match policy.action_classes.get(UNPARSED_LINE_ACTION_TYPE) {
        None => Ok(()),
        Some(class) => Err(format!(
            "action_classes declares {UNPARSED_LINE_ACTION_TYPE:?} ({class:?}): praetore-mcp reserves that action type for the signed receipt of a client line it cannot parse; remove it from action_classes"
        )),
    }
}

/// At most this many tool names read by the tolerant reader are recorded.
pub const MAX_TOLERANT_TOOLS: usize = 8;
/// Of each recorded tool name, the first this many characters are kept,
/// then escaped (an escape is longer than its character), with `…` added
/// when the name was cut ([`crate::shown::bounded`]).
pub const MAX_TOLERANT_TOOL_CHARS: usize = 128;

/// Why the strict parser rejected a line: a closed set, not the parser's
/// free text, so receipts from different versions compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorClass {
    InvalidUtf8,
    DuplicateKey,
    LoneSurrogate,
    Depth,
    NumberRange,
    Syntax,
}

impl ParseErrorClass {
    /// The class of `raw`, rejected by the strict parser with `reason`.
    /// Invalid UTF-8 is read from the bytes; the other classes from the
    /// message of the pinned `serde_json` and of [`crate::json`] (each one
    /// has a test). Anything else is `syntax`.
    pub fn of(raw: &[u8], reason: &str) -> Self {
        if std::str::from_utf8(raw).is_err() {
            Self::InvalidUtf8
        } else if reason.starts_with("duplicate object key") {
            Self::DuplicateKey
        } else if reason.contains("surrogate") || reason.starts_with("unexpected end of hex escape")
        {
            Self::LoneSurrogate
        } else if reason.starts_with("recursion limit exceeded") {
            Self::Depth
        } else if reason.starts_with("number out of range") {
            Self::NumberRange
        } else {
            Self::Syntax
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "invalid_utf8",
            Self::DuplicateKey => "duplicate_key",
            Self::LoneSurrogate => "lone_surrogate",
            Self::Depth => "depth",
            Self::NumberRange => "number_range",
            Self::Syntax => "syntax",
        }
    }
}

/// What the receipt of one unparseable line records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnparsedLine {
    /// SHA-256 of the raw bytes as received (with the newline, if any): the
    /// same bytes the stderr notice fingerprints, never a reserialization.
    pub line_sha256: String,
    pub line_len: usize,
    pub parse_error: ParseErrorClass,
    /// Tool names a tolerant reader sees in a `tools/call` ([`tolerant_tools`]).
    /// Recorded only.
    pub tolerant_tools: Vec<String>,
    /// [`crate::proxy::may_name_safety_tool`]: the line is refused in both
    /// modes (G7). Signed so the receipt says why an observe line was not
    /// forwarded.
    pub may_name_safety: bool,
}

impl UnparsedLine {
    pub fn of(raw: &[u8], reason: &str) -> Self {
        Self {
            line_sha256: hex::encode(Sha256::digest(raw)),
            line_len: raw.len(),
            parse_error: ParseErrorClass::of(raw, reason),
            tolerant_tools: tolerant_tools(raw),
            may_name_safety: crate::proxy::may_name_safety_tool(raw),
        }
    }

    /// The signed action parameters.
    pub fn parameters(&self, server: &str, mode: Mode) -> Value {
        json!({
            "server": server,
            "mode": mode.as_str(),
            "line_sha256": self.line_sha256,
            "line_len": self.line_len,
            "parse_error": self.parse_error.as_str(),
            "tolerant_tools": self.tolerant_tools,
            "may_name_safety": self.may_name_safety,
        })
    }
}

/// How readers show the receipt of an unparseable line in the TOOL column:
/// `UNPARSED <first 12 hex of line_sha256>`. `None` for any other receipt.
pub fn reader_label(action_type: &str, parameters: &Value) -> Option<String> {
    if action_type != UNPARSED_LINE_ACTION_TYPE {
        return None;
    }
    let digest = parameters
        .get("line_sha256")
        .and_then(Value::as_str)
        .unwrap_or("?");
    Some(format!(
        "UNPARSED {}",
        digest.chars().take(12).collect::<String>()
    ))
}

/// Tool names that a tolerant reader finds in the `tools/call` message(s)
/// of `raw`, escaped and bounded. The reader is the one research note 22
/// fixes in writing: invalid UTF-8 becomes U+FFFD; of a duplicated key both
/// the first and the last value are readings; a lone surrogate escape is
/// accepted (kept as U+FFFD); no depth limit, and numbers are not range
/// checked. A line it cannot read either gives no names.
pub fn tolerant_tools(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let Some(messages) = scan(text.as_bytes()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for message in &messages {
        if !first_and_last(&message.methods)
            .iter()
            .any(|method| method == "tools/call")
        {
            continue;
        }
        for params in first_and_last(&message.params) {
            for name in first_and_last(&params) {
                let shown = crate::shown::bounded(&name, MAX_TOLERANT_TOOL_CHARS);
                if !names.contains(&shown) && names.len() < MAX_TOLERANT_TOOLS {
                    names.push(shown);
                }
            }
        }
    }
    names
}

fn first_and_last<T: Clone>(values: &[T]) -> Vec<T> {
    match values {
        [] => Vec::new(),
        [only] => vec![only.clone()],
        [first, .., last] => vec![first.clone(), last.clone()],
    }
}

/// One message object (the line, or an element of a top-level array).
#[derive(Default)]
struct Message {
    /// Every string value of a `method` member, in order.
    methods: Vec<String>,
    /// For every `params` object member, the string values of its `name`
    /// members, in order.
    params: Vec<Vec<String>>,
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Value,
    ValueOrClose,
    Key,
    KeyOrClose,
    After,
}

/// The tolerant reader. Iterative, so depth costs one byte of stack per
/// level and no recursion. Only the members it records are kept: keys at
/// the first three levels and the strings at the paths of `method` and
/// `params.name`.
fn scan(bytes: &[u8]) -> Option<Vec<Message>> {
    let mut at = 0;
    let mut stack: Vec<u8> = Vec::new();
    let mut keys: [String; 3] = Default::default();
    let mut messages = Vec::new();
    let mut current: Option<Message> = None;
    let mut state = State::Value;
    loop {
        while bytes.get(at).is_some_and(|b| b" \t\r\n".contains(b)) {
            at += 1;
        }
        if stack.is_empty() && state == State::After {
            return (at == bytes.len()).then_some(messages);
        }
        // The message object sits at depth `base`: 0 for a single message,
        // 1 inside a top-level array (a batch).
        let base = usize::from(stack.first() == Some(&b'['));
        match state {
            State::Value | State::ValueOrClose => match *bytes.get(at)? {
                b']' if state == State::ValueOrClose => {
                    at += 1;
                    stack.pop();
                    state = State::After;
                }
                b'{' => {
                    at += 1;
                    if stack.len() == base {
                        current = Some(Message::default());
                    } else if stack.len() == base + 1
                        && stack[base] == b'{'
                        && keys[base] == "params"
                        && let Some(message) = current.as_mut()
                    {
                        message.params.push(Vec::new());
                    }
                    stack.push(b'{');
                    state = State::KeyOrClose;
                }
                b'[' => {
                    at += 1;
                    stack.push(b'[');
                    state = State::ValueOrClose;
                }
                b'"' => {
                    let value = string(bytes, &mut at)?;
                    if let Some(message) = current.as_mut() {
                        let depth = stack.len();
                        if depth == base + 1 && stack[base] == b'{' && keys[base] == "method" {
                            message.methods.push(value);
                        } else if depth == base + 2
                            && stack[base] == b'{'
                            && stack[base + 1] == b'{'
                            && keys[base] == "params"
                            && keys[base + 1] == "name"
                            && let Some(names) = message.params.last_mut()
                        {
                            names.push(value);
                        }
                    }
                    state = State::After;
                }
                _ => {
                    scalar(bytes, &mut at)?;
                    state = State::After;
                }
            },
            State::Key | State::KeyOrClose => match *bytes.get(at)? {
                b'}' if state == State::KeyOrClose => {
                    at += 1;
                    close_object(&mut stack, base, &mut current, &mut messages);
                    state = State::After;
                }
                b'"' => {
                    let key = string(bytes, &mut at)?;
                    if let Some(slot) = keys.get_mut(stack.len() - 1) {
                        *slot = key;
                    }
                    while bytes.get(at).is_some_and(|b| b" \t\r\n".contains(b)) {
                        at += 1;
                    }
                    if bytes.get(at) != Some(&b':') {
                        return None;
                    }
                    at += 1;
                    state = State::Value;
                }
                _ => return None,
            },
            State::After => {
                let top = *stack.last()?;
                match (*bytes.get(at)?, top) {
                    (b',', b'{') => state = State::Key,
                    (b',', _) => state = State::Value,
                    (b'}', b'{') => close_object(&mut stack, base, &mut current, &mut messages),
                    (b']', b'[') => {
                        stack.pop();
                    }
                    _ => return None,
                }
                at += 1;
            }
        }
    }
}

fn close_object(
    stack: &mut Vec<u8>,
    base: usize,
    current: &mut Option<Message>,
    messages: &mut Vec<Message>,
) {
    stack.pop();
    if stack.len() == base
        && let Some(message) = current.take()
    {
        messages.push(message);
    }
}

/// A JSON string starting at the opening quote. Escapes are decoded; a lone
/// surrogate becomes U+FFFD. A raw control character is accepted.
fn string(bytes: &[u8], at: &mut usize) -> Option<String> {
    *at += 1;
    let mut units: Vec<u16> = Vec::new();
    let start = *at;
    let mut plain = start;
    loop {
        match *bytes.get(*at)? {
            b'"' => {
                push_text(&mut units, &bytes[plain..*at]);
                *at += 1;
                return Some(String::from_utf16_lossy(&units));
            }
            b'\\' => {
                push_text(&mut units, &bytes[plain..*at]);
                let escape = *bytes.get(*at + 1)?;
                *at += 2;
                match escape {
                    b'"' => units.push(u16::from(b'"')),
                    b'\\' => units.push(u16::from(b'\\')),
                    b'/' => units.push(u16::from(b'/')),
                    b'b' => units.push(0x08),
                    b'f' => units.push(0x0c),
                    b'n' => units.push(u16::from(b'\n')),
                    b'r' => units.push(u16::from(b'\r')),
                    b't' => units.push(u16::from(b'\t')),
                    b'u' => {
                        let hex = std::str::from_utf8(bytes.get(*at..*at + 4)?).ok()?;
                        units.push(u16::from_str_radix(hex, 16).ok()?);
                        *at += 4;
                    }
                    _ => return None,
                }
                plain = *at;
            }
            _ => *at += 1,
        }
    }
}

fn push_text(units: &mut Vec<u16>, text: &[u8]) {
    // `text` is a slice of a `str` between ASCII delimiters.
    units.extend(String::from_utf8_lossy(text).encode_utf16());
}

/// `true`, `false`, `null` or a number (any magnitude).
fn scalar(bytes: &[u8], at: &mut usize) -> Option<()> {
    let start = *at;
    while bytes
        .get(*at)
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"+-.".contains(b))
    {
        *at += 1;
    }
    let token = &bytes[start..*at];
    if matches!(token, b"true" | b"false" | b"null") || is_number(token) {
        Some(())
    } else {
        None
    }
}

fn is_number(token: &[u8]) -> bool {
    let mut rest = token.strip_prefix(b"-").unwrap_or(token);
    let digits = |rest: &mut &[u8]| {
        let count = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        *rest = &rest[count..];
        count
    };
    if digits(&mut rest) == 0 {
        return false;
    }
    if let Some(after) = rest.strip_prefix(b".") {
        rest = after;
        if digits(&mut rest) == 0 {
            return false;
        }
    }
    if let Some(after) = rest.strip_prefix(b"e").or_else(|| rest.strip_prefix(b"E")) {
        rest = after
            .strip_prefix(b"+")
            .or_else(|| after.strip_prefix(b"-"))
            .unwrap_or(after);
        if digits(&mut rest) == 0 {
            return false;
        }
    }
    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gate::Gate,
        proxy::{Classified, classify, handle_client_line},
        store::{self, Home},
    };
    use praetore_core::{ActionClass, DecisionOutcome, Evidence};
    use std::fs;

    /// Rows 1, 4, 5, 6 and 7 of the research note 22 corpus, as client
    /// lines: each is a `tools/call` of `write_file` the strict parser
    /// rejects, with the class it must record.
    fn corpus() -> Vec<(&'static str, Vec<u8>, ParseErrorClass)> {
        let call = |arguments: &str| {
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"write_file\",\"arguments\":{arguments}}}}}\n"
            )
            .into_bytes()
        };
        let mut invalid_utf8 = call("{\"path\":\"/tmp/X\"}");
        let at = invalid_utf8.iter().position(|&b| b == b'X').unwrap();
        invalid_utf8[at] = 0xff;
        vec![
            (
                "1 duplicate key",
                call("{\"path\":\"/a\",\"path\":\"/b\"}"),
                ParseErrorClass::DuplicateKey,
            ),
            (
                "4 invalid UTF-8",
                invalid_utf8,
                ParseErrorClass::InvalidUtf8,
            ),
            (
                "5 lone surrogate",
                call("{\"path\":\"\\ud800\"}"),
                ParseErrorClass::LoneSurrogate,
            ),
            (
                "6 depth",
                call(&format!(
                    "{{\"a\":{}1{}}}",
                    "[".repeat(200),
                    "]".repeat(200)
                )),
                ParseErrorClass::Depth,
            ),
            (
                "7 number range",
                call("{\"n\":1E400}"),
                ParseErrorClass::NumberRange,
            ),
        ]
    }

    fn sha256(raw: &[u8]) -> String {
        hex::encode(Sha256::digest(raw))
    }

    fn reason(raw: &[u8]) -> String {
        match classify(raw) {
            Classified::Unparseable(reason) => reason,
            other => panic!("not unparseable: {other:?}"),
        }
    }

    /// An initialized home with its own policy id (the probe counters are
    /// per policy id) and a working receipts journal.
    fn home(policy_id: &str) -> (tempfile::TempDir, Home) {
        let temp = tempfile::tempdir().unwrap();
        let home = Home::new(fs::canonicalize(temp.path()).unwrap().join("home"));
        store::init(&home).unwrap();
        let mut policy = store::default_policy();
        policy.id = policy_id.to_owned();
        fs::write(home.policy(), serde_json::to_vec_pretty(&policy).unwrap()).unwrap();
        (temp, home)
    }

    fn receipts(home: &Home) -> Vec<Evidence> {
        crate::receipts::read_journal(home)
            .unwrap()
            .iter()
            .map(|line| crate::journal::parse_line(&line.text).unwrap().evidence)
            .collect()
    }

    fn assert_unparsed_receipt(evidence: &Evidence, raw: &[u8], mode: Mode, label: &str) {
        assert_eq!(
            evidence.action.action_type, UNPARSED_LINE_ACTION_TYPE,
            "{label}"
        );
        let parameters = &evidence.action.parameters;
        assert_eq!(parameters["line_sha256"], sha256(raw), "{label}");
        assert_eq!(parameters["line_len"], raw.len(), "{label}");
        assert_eq!(parameters["mode"], mode.as_str(), "{label}");
        assert_eq!(parameters["server"], "fs", "{label}");
        assert_eq!(
            parameters["may_name_safety"],
            crate::proxy::may_name_safety_tool(raw),
            "{label}"
        );
        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny, "{label}");
        assert_eq!(
            evidence.decision.decided_by(),
            Some(&praetore_core::DecidedBy::engine_guard(
                praetore_core::UNCLASSIFIED_ACTION_GUARD
            )),
            "{label}"
        );
        evidence.verify_agent_intent().unwrap();
    }

    fn assert_journal_verifies(home: &Home) {
        let report = crate::receipts::verify_journal(home, None).unwrap();
        assert!(report.failures.is_empty(), "{:?}", report.failures);
    }

    /// The strict parser's reason maps to the closed class (the messages
    /// of the pinned `serde_json` and of `json.rs`).
    #[test]
    fn parse_error_is_one_of_the_closed_classes() {
        for (label, raw, class) in corpus() {
            assert_eq!(ParseErrorClass::of(&raw, &reason(&raw)), class, "{label}");
        }
        // serde_json words a lone surrogate two ways: a high one before a
        // non-escape ("unexpected end of hex escape", row 5) and one before
        // another escape that is not its low half ("lone leading surrogate").
        let before_escape = br#"{"p":"\ud800\u0041"}"#;
        assert_eq!(
            ParseErrorClass::of(before_escape, &reason(before_escape)),
            ParseErrorClass::LoneSurrogate,
            "{}",
            reason(before_escape)
        );
        let garbage = b"this is not json\n";
        assert_eq!(
            ParseErrorClass::of(garbage, &reason(garbage)),
            ParseErrorClass::Syntax
        );
    }

    /// Observe: each corpus row is forwarded byte for byte, after exactly
    /// one `mcp.unparsed_line` receipt over the raw bytes, a signed DENY by
    /// the unclassified-action guard; no rule is evaluated and the journal
    /// still verifies.
    #[test]
    fn observe_unparseable_line_writes_one_unparsed_line_receipt() {
        let policy_id = "b4-observe";
        let (_temp, home) = home(policy_id);
        let mut gate = Gate::load(&home, Mode::Observe).unwrap();
        for (index, (label, raw, class)) in corpus().into_iter().enumerate() {
            let out = handle_client_line(&raw, Mode::Observe, "fs", &mut gate);
            assert_eq!(out.to_server.as_deref(), Some(&raw[..]), "{label}");
            assert!(out.to_client.is_none(), "{label}");
            assert!(
                out.warnings[0].contains("signed receipt mcp.unparsed_line"),
                "{label}: {:?}",
                out.warnings
            );
            let all = receipts(&home);
            assert_eq!(all.len(), index + 1, "{label}: one receipt per line");
            let evidence = all.last().unwrap();
            assert_unparsed_receipt(evidence, &raw, Mode::Observe, label);
            assert_eq!(
                evidence.action.parameters["parse_error"],
                class.as_str(),
                "{label}"
            );
        }
        assert_eq!(praetore_core::probe::policy_evaluations(policy_id), 0);
        assert_journal_verifies(&home);
    }

    /// Enforce: the line is refused with `-32700` as before, nothing is
    /// forwarded, and the refusal now has its receipt.
    #[test]
    fn enforce_unparseable_writes_one_receipt_and_forwards_nothing() {
        let (_temp, home) = home("b4-enforce");
        let mut gate = Gate::load(&home, Mode::Enforce).unwrap();
        for (index, (label, raw, _)) in corpus().into_iter().enumerate() {
            let out = handle_client_line(&raw, Mode::Enforce, "fs", &mut gate);
            assert!(out.to_server.is_none(), "{label}");
            let reply: Value = serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
            assert_eq!(reply["error"]["code"], -32700, "{label}");
            let all = receipts(&home);
            assert_eq!(all.len(), index + 1, "{label}");
            assert_unparsed_receipt(all.last().unwrap(), &raw, Mode::Enforce, label);
        }
        assert_journal_verifies(&home);
    }

    /// Invalid UTF-8 inside a `tools/call`: the tolerant reader (U+FFFD)
    /// sees `write_file`, and the receipt records it.
    #[test]
    fn unparsed_line_receipt_records_tolerant_tool_names() {
        let (_temp, home) = home("b4-tolerant");
        let mut gate = Gate::load(&home, Mode::Observe).unwrap();
        let raw = &corpus()[1].1;
        handle_client_line(raw, Mode::Observe, "fs", &mut gate);
        let all = receipts(&home);
        assert_eq!(
            all[0].action.parameters["tolerant_tools"],
            json!(["write_file"])
        );
    }

    #[test]
    fn plain_garbage_gets_a_receipt_with_no_tolerant_tools() {
        let (_temp, home) = home("b4-garbage");
        let mut gate = Gate::load(&home, Mode::Observe).unwrap();
        let raw = b"this is not json\n";
        let out = handle_client_line(raw, Mode::Observe, "fs", &mut gate);
        assert_eq!(out.to_server.as_deref(), Some(&raw[..]));
        let all = receipts(&home);
        assert_eq!(all.len(), 1);
        assert_unparsed_receipt(&all[0], raw, Mode::Observe, "garbage");
        assert_eq!(all[0].action.parameters["tolerant_tools"], json!([]));
        assert_eq!(all[0].action.parameters["parse_error"], "syntax");
    }

    /// Lines that may name a `safety*` tool (G7, #220): the JSON5 line
    /// naming `safety_x` and the duplicate-key line naming `safety:halt`.
    const SAFETY_NAMED: [&[u8]; 2] = [
        b"{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'safety_x',arguments:{}},}\n",
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safety:halt","name":"x"}}
"#,
    ];

    /// A line that may name a `safety*` tool is still refused in both modes,
    /// and now with one `mcp.unparsed_line` receipt signed with
    /// `may_name_safety: true`, written before the `-32700`. The journal
    /// verifies.
    #[test]
    fn safety_named_unparseable_is_refused_with_a_receipt_in_both_modes() {
        for mode in [Mode::Observe, Mode::Enforce] {
            for raw in SAFETY_NAMED {
                let label = format!("{} {}", mode.as_str(), String::from_utf8_lossy(raw));
                let (_temp, home) = home(&format!("b4-safety-{}", mode.as_str()));
                let mut gate = Gate::load(&home, mode).unwrap();
                assert!(crate::proxy::may_name_safety_tool(raw), "{label}");
                let out = handle_client_line(raw, mode, "fs", &mut gate);
                assert!(out.to_server.is_none(), "{label}");
                let reply: Value =
                    serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                assert_eq!(reply["error"]["code"], -32700, "{label}");
                assert_eq!(out.warnings.len(), 1, "{label}: {:?}", out.warnings);
                assert!(
                    out.warnings[0].contains("may name a safety* tool")
                        && out.warnings[0].contains("signed receipt mcp.unparsed_line"),
                    "{label}: {:?}",
                    out.warnings
                );
                let written = receipts(&home);
                assert_eq!(written.len(), 1, "{label}");
                assert_unparsed_receipt(&written[0], raw, mode, &label);
                assert_eq!(
                    written[0].action.parameters["may_name_safety"], true,
                    "{label}"
                );
                assert_journal_verifies(&home);
            }
        }
    }

    /// The refusal of a line that may name a `safety*` tool does not depend
    /// on its receipt: with the journal down it is refused all the same, in
    /// both modes, and the notice says the receipt could NOT be written.
    #[test]
    fn safety_named_unparseable_is_refused_even_when_its_receipt_cannot_be_written() {
        for mode in [Mode::Observe, Mode::Enforce] {
            for raw in SAFETY_NAMED {
                let label = format!("{} {}", mode.as_str(), String::from_utf8_lossy(raw));
                let (_temp, home) = home(&format!("b4-safety-down-{}", mode.as_str()));
                let receipts_dir = home.receipts_dir();
                let _ = fs::remove_dir_all(&receipts_dir);
                fs::write(&receipts_dir, b"down\n").unwrap();
                let mut gate = Gate::load(&home, mode).unwrap();
                let out = handle_client_line(raw, mode, "fs", &mut gate);
                assert!(out.to_server.is_none(), "{label}");
                let reply: Value =
                    serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                assert_eq!(reply["error"]["code"], -32700, "{label}");
                assert_eq!(out.warnings.len(), 1, "{label}: {:?}", out.warnings);
                assert!(
                    out.warnings[0].contains("may name a safety* tool")
                        && out.warnings[0].contains("receipt mcp.unparsed_line")
                        && out.warnings[0].contains("could NOT be written"),
                    "{label}: {:?}",
                    out.warnings
                );
                assert_eq!(fs::read(&receipts_dir).unwrap(), b"down\n", "{label}");
            }
        }
    }

    /// The journal is down (`receipts` is a file). Observe follows the rule
    /// for a receipt that cannot be written: the line is forwarded and the
    /// notice says so before anything else. Enforce still forwards nothing.
    #[test]
    fn unparsed_receipt_that_cannot_be_written_forwards_in_observe_and_refuses_in_enforce() {
        for mode in [Mode::Observe, Mode::Enforce] {
            let (_temp, home) = home(&format!("b4-journal-down-{}", mode.as_str()));
            let receipts_dir = home.receipts_dir();
            let _ = fs::remove_dir_all(&receipts_dir);
            fs::write(&receipts_dir, b"down\n").unwrap();
            let mut gate = Gate::load(&home, mode).unwrap();
            let raw = b"this is not json\n";
            let out = handle_client_line(raw, mode, "fs", &mut gate);
            assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
            assert!(
                out.warnings[0].contains("receipt mcp.unparsed_line")
                    && out.warnings[0].contains("could NOT be written"),
                "{:?}",
                out.warnings
            );
            match mode {
                Mode::Observe => assert_eq!(out.to_server.as_deref(), Some(&raw[..])),
                Mode::Enforce => {
                    assert!(out.to_server.is_none());
                    let reply: Value =
                        serde_json::from_slice(out.to_client.as_deref().unwrap()).unwrap();
                    assert_eq!(reply["error"]["code"], -32700);
                }
            }
            assert_eq!(fs::read(&receipts_dir).unwrap(), b"down\n");
        }
    }

    /// The type is reserved. A policy that declares it as Mission (valid
    /// for the core) is refused by `policy check` (exit 1), by loading the
    /// home (`Gate::load`, what `wrap` does) and by the `policy` edits, which
    /// leave the file as it was. As Safety, the core already refuses it.
    #[test]
    fn a_policy_that_declares_the_unparsed_type_is_refused_by_check_load_and_edits() {
        let declared = |class| {
            let mut policy = store::default_policy();
            policy.id = "b4-declared".into();
            policy
                .action_classes
                .insert(UNPARSED_LINE_ACTION_TYPE.to_owned(), class);
            policy
        };
        let as_safety = serde_json::to_string(&declared(ActionClass::Safety)).unwrap();
        assert!(praetore_core::Policy::from_json(&as_safety).is_err());
        let (_temp, home) = home("b4-declared");
        let policy = declared(ActionClass::Mission);
        assert!(praetore_core::Policy::from_json(&serde_json::to_string(&policy).unwrap()).is_ok());
        let text = serde_json::to_vec_pretty(&policy).unwrap();
        fs::write(home.policy(), &text).unwrap();
        let refused =
            |error: &str| error.contains(UNPARSED_LINE_ACTION_TYPE) && error.contains("reserves");

        let error = refuse_reserved_type(&policy).unwrap_err();
        assert!(refused(&error), "{error}");
        for mode in [Mode::Observe, Mode::Enforce] {
            let error = Gate::load(&home, mode).err().expect("Gate::load refused");
            assert!(refused(&error), "{error}");
        }
        let error = crate::policy::render_validated(&policy).unwrap_err();
        assert!(refused(&error), "{error}");

        let dir = home.root.to_str().unwrap().to_owned();
        // `policy` subcommands only (never the whole CLI dispatch).
        let cli = |args: &[&str]| {
            crate::cli::cmd_policy(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(cli(&["check", "--dir", &dir]), Ok(1));
        let edit = cli(&[
            "allow", "--id", "b4-allow", "--server", "fs", "--tool", "read", "--dir", &dir,
        ]);
        assert!(edit.as_ref().is_err_and(|e| refused(e)), "{edit:?}");
        assert_eq!(fs::read(home.policy()).unwrap(), text);

        let clean = serde_json::to_vec_pretty(&store::default_policy()).unwrap();
        fs::write(home.policy(), clean).unwrap();
        assert_eq!(cli(&["check", "--dir", &dir]), Ok(0), "clean policy");
    }

    /// Readers show the receipt as `UNPARSED <sha256 prefix>`: the
    /// `receipts` table, the dashboard and the session report.
    #[test]
    fn readers_show_the_unparsed_receipt_as_unparsed() {
        let (_temp, home) = home("b4-readers");
        let mut gate = Gate::load(&home, Mode::Observe).unwrap();
        let raw = b"this is not json\n";
        handle_client_line(raw, Mode::Observe, "fs", &mut gate);
        let label = format!("UNPARSED {}", &sha256(raw)[..12]);
        let lines = crate::receipts::read_journal(&home).unwrap();
        let table = crate::receipts::render_table(&lines, 10, &Default::default());
        assert!(table.contains(&label), "{table}");
        let state = crate::dashboard::state(&home, None);
        assert_eq!(state["receipts"][0]["tool"], label.as_str(), "{state}");
        let id = receipts(&home)[0].evidence_id.to_string();
        let now = time::OffsetDateTime::now_utc();
        let generated = crate::report::generate(
            &home,
            crate::report::Source {
                meta: crate::report::SessionMeta {
                    id: "0b4a0b4a".into(),
                    server: "fs".into(),
                    mode: "observe".into(),
                    started_at: now,
                    ended_at: now,
                },
                evidence_ids: vec![id],
                close_heads: None,
                agent: None,
                regenerated_from: None,
            },
        )
        .unwrap();
        let pdf = fs::read(generated.pdf).unwrap();
        let shown = format!("({label})");
        assert!(
            pdf.windows(shown.len()).any(|w| w == shown.as_bytes()),
            "the PDF has no {shown}"
        );
    }

    /// The tolerant reader as research note 22 fixes it.
    #[test]
    fn tolerant_reader_reads_first_and_last_duplicates_batches_and_depth() {
        let names = |raw: &[u8]| tolerant_tools(raw);
        assert_eq!(
            names(br#"{"method":"tools/call","params":{"name":"a","name":"b","name":"c"}}"#),
            ["a", "c"]
        );
        assert_eq!(
            names(br#"{"method":"tools/list","method":"tools/call","params":{"name":"a"}}"#),
            ["a"]
        );
        assert_eq!(
            names(br#"{"method":"tools/list","params":{"name":"a"}}"#),
            Vec::<String>::new()
        );
        assert_eq!(
            names(br#"[{"method":"tools/call","params":{"name":"a"}},{"method":"tools/call","params":{"name":"b"}}]"#),
            ["a", "b"]
        );
        assert_eq!(
            names(br#"{"method":"tools/call","params":{"name":"\ud800x"}}"#),
            ["\u{fffd}x"]
        );
        assert_eq!(
            names(br#"{"method":"tools/call","params":{"name":"a\u001b[2K"}}"#),
            ["a\\u{1b}[2K"]
        );
        // Nested names are not the tool name.
        assert_eq!(
            names(br#"{"method":"tools/call","params":{"arguments":{"name":"x"},"name":"a"}}"#),
            ["a"]
        );
        let deep = format!(
            "{{\"method\":\"tools/call\",\"params\":{{\"name\":\"a\",\"arguments\":{}1{}}}}}",
            "[".repeat(1_000_000),
            "]".repeat(1_000_000)
        );
        assert_eq!(names(deep.as_bytes()), ["a"]);
        let many: Vec<String> = (0..20)
            .map(|i| format!(r#"{{"method":"tools/call","params":{{"name":"t{i}"}}}}"#))
            .collect();
        let batch = format!("[{}]", many.join(","));
        assert_eq!(names(batch.as_bytes()).len(), MAX_TOLERANT_TOOLS);
        let long = format!(
            r#"{{"method":"tools/call","params":{{"name":"{}"}}}}"#,
            "n".repeat(1000)
        );
        assert_eq!(
            names(long.as_bytes())[0].chars().count(),
            MAX_TOLERANT_TOOL_CHARS + 1
        );
        assert!(names(b"{\"method\":\"tools/call\",").is_empty());
        assert!(
            names(b"{\"method\":\"tools/call\",\"params\":{\"name\":\"a\"}} trailing").is_empty()
        );
    }
}
