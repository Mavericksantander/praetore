//! Plain-language reading of one journal receipt.
//!
//! The words an operator sees are decided here. Technical state names stay in
//! this module and are not the product face.

use praetore_core::{Evidence, VerifiedPublicKey};
use praetore_gateway::{
    AttestedExecution, AuthorizationStatus, ExecutionStatus, NotDispatchedReason,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::{Date, Duration, Month, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::codigos::{AgentView, Placeholder, ShownText};
pub use crate::codigos::{Notice, Situation, Story};

impl Situation {
    /// A history filter: the code (`awaiting_approval`) or, as the page sent
    /// it before codes, the Spanish phrase (`pendiente de aprobación`).
    /// `unreadable` is not a filter.
    pub fn parse(value: &str) -> Option<Self> {
        let parsed = Self::from_code(value).or_else(|| {
            Self::ALL
                .iter()
                .copied()
                .find(|situation| situation.legacy_phrase() == Some(value))
        })?;
        (parsed != Self::Unreadable).then_some(parsed)
    }

    /// The Spanish phrase the filter used to send, accepted for
    /// compatibility. Never shown: the page words each code itself.
    fn legacy_phrase(self) -> Option<&'static str> {
        Some(match self {
            Self::Permitted => "permitido",
            Self::Denied => "denegado",
            Self::Approved => "aprobado",
            Self::Rejected => "rechazado",
            Self::Expired => "expirado",
            Self::AwaitingApproval => "pendiente de aprobación",
            Self::ApprovedPendingExecution => "aprobado, pendiente de ejecución",
            Self::NotExecuted => "no se ejecutó",
            Self::Unreadable => return None,
        })
    }
}

/// The notice under the history: a receipt is not a current authorization.
pub const NOTICE: Notice = Notice::ReceiptNotAuthorization;

/// One journal row, already reduced to what the console is allowed to say.
#[derive(Debug, Clone)]
pub struct ReceiptFacts {
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub attested: Option<AttestedExecution>,
    pub reason: Option<NotDispatchedReason>,
    pub legible: bool,
    pub wanted: String,
    pub target: Option<String>,
}

/// Columns the console reads. Evidence JSON is consumed here and not kept.
pub struct JournalColumns {
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub attested: Option<AttestedExecution>,
    pub reason: Option<NotDispatchedReason>,
    pub evidence_json: String,
}

/// A receipt whose evidence does not check out is kept as unreadable
/// (`legible: false`, no action or target): one bad receipt does not hide
/// the rest of the page. With `pins`, the evidence must also be signed by
/// one of them; the current policy is not required, so a receipt decided
/// under an earlier policy stays readable. Without pins, integrity only.
pub fn facts_from_columns(
    columns: JournalColumns,
    pins: Option<&[VerifiedPublicKey]>,
) -> ReceiptFacts {
    let (legible, action) = match public_action(&columns.evidence_json, pins) {
        Ok(action) => (true, action),
        Err(()) => (
            false,
            PublicAction {
                wanted: String::new(),
                target: None,
            },
        ),
    };
    ReceiptFacts {
        created_at: columns.created_at,
        updated_at: columns.updated_at,
        agent_id: columns.agent_id,
        request_id: columns.request_id,
        authorization: columns.authorization,
        execution: columns.execution,
        attested: columns.attested,
        reason: columns.reason,
        legible,
        wanted: action.wanted,
        target: action.target,
    }
}

pub struct PublicAction {
    pub wanted: String,
    pub target: Option<String>,
}

/// Action type and target when the receipt still checks out: integrity,
/// and with `pins` the attester signature of one of them. Parameters,
/// context, and the raw JSON are dropped.
pub fn public_action(
    evidence_json: &str,
    pins: Option<&[VerifiedPublicKey]>,
) -> Result<PublicAction, ()> {
    let evidence = Evidence::from_json(evidence_json).map_err(|_| ())?;
    // `from_json` already refuses a receipt that does not check out. A second
    // check keeps a tampered target from being copied if that ever changes.
    if !evidence.verify_integrity() {
        return Err(());
    }
    if pins.is_some_and(|pins| !crate::confianza::signed_by_a_pin(&evidence, pins)) {
        return Err(());
    }
    let target = evidence.action.target.filter(|target| !target.is_empty());
    Ok(PublicAction {
        wanted: evidence.action.action_type,
        target,
    })
}

pub fn situation(facts: &ReceiptFacts) -> Situation {
    if !facts.legible {
        return Situation::Unreadable;
    }
    if facts.authorization == AuthorizationStatus::Denied {
        return Situation::Denied;
    }
    if facts.execution == ExecutionStatus::ApprovedPendingDispatch {
        return Situation::ApprovedPendingExecution;
    }
    if facts.reason == Some(NotDispatchedReason::ApprovalRejected) {
        return Situation::Rejected;
    }
    if matches!(
        facts.reason,
        Some(NotDispatchedReason::ApprovalExpired | NotDispatchedReason::ApprovedClaimExpired)
    ) {
        return Situation::Expired;
    }
    // `awaiting_approval` is a signed receipt state. Its journal row stays
    // `not_dispatched` with no close reason. A hold from before that receipt
    // has the same row shape and the same words.
    let awaiting = facts.attested == Some(AttestedExecution::AwaitingApproval)
        || (facts.authorization == AuthorizationStatus::RequiresApproval
            && facts.execution == ExecutionStatus::NotDispatched
            && facts.reason.is_none());
    if awaiting {
        return Situation::AwaitingApproval;
    }
    if facts.authorization == AuthorizationStatus::Allowed {
        return Situation::Permitted;
    }
    if facts.authorization == AuthorizationStatus::RequiresApproval
        && facts.execution != ExecutionStatus::NotDispatched
    {
        return Situation::Approved;
    }
    if facts.authorization == AuthorizationStatus::RequiresApproval {
        return Situation::NotExecuted;
    }
    Situation::Unreadable
}

pub fn story(facts: &ReceiptFacts) -> Story {
    match situation(facts) {
        Situation::Unreadable => Story::Unreadable,
        Situation::Denied => Story::Denied,
        Situation::Rejected => Story::Rejected,
        Situation::Expired => match facts.reason {
            Some(NotDispatchedReason::ApprovedClaimExpired) => Story::ExpiredAfterApproval,
            _ => Story::ExpiredWithoutDecision,
        },
        Situation::AwaitingApproval => Story::AwaitingApproval,
        Situation::ApprovedPendingExecution => Story::ApprovedPendingExecution,
        Situation::Permitted => match facts.execution {
            ExecutionStatus::Executed | ExecutionStatus::Confirmed => Story::PermittedExecuted,
            ExecutionStatus::Failed => Story::PermittedFailed,
            ExecutionStatus::OutcomeUnknown => Story::PermittedOutcomeUnknown,
            ExecutionStatus::Dispatched => Story::PermittedDispatched,
            ExecutionStatus::NotDispatched => Story::PermittedNotExecuted,
            ExecutionStatus::Authorized | ExecutionStatus::ApprovedPendingDispatch => {
                Story::PermittedNotYetExecuted
            }
        },
        Situation::Approved => match facts.execution {
            ExecutionStatus::Executed | ExecutionStatus::Confirmed => Story::ApprovedExecuted,
            ExecutionStatus::Failed => Story::ApprovedFailed,
            ExecutionStatus::OutcomeUnknown => Story::ApprovedOutcomeUnknown,
            ExecutionStatus::Dispatched => Story::ApprovedDispatched,
            _ => Story::Approved,
        },
        Situation::NotExecuted => match facts.reason {
            Some(NotDispatchedReason::DispatchRefused) => Story::NotExecutedRefused,
            _ => Story::NotExecuted,
        },
    }
}

/// Text the agent chose, made safe to read: control and bidirectional
/// override characters are shown as `\u{...}` instead of acting on the
/// page (a target like `informe\u{202e}fdp.exe` cannot disguise itself).
pub fn plain_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        push_inert(&mut safe, character);
    }
    safe
}

/// Like [`plain_text`], and a backslash is shown doubled, so text that
/// spells out an escape (`\u{202e}`) never looks like the escaped character.
/// Used in the approvals inbox, which must tell apart structure, types and
/// hidden characters of what is signed.
pub fn unambiguous_text(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\\' {
            safe.push_str("\\\\");
        } else {
            push_inert(&mut safe, character);
        }
    }
    safe
}

/// Agent text in quotes, with `"` and `\\` escaped and hidden characters
/// shown as `\u{xxxx}`: a value "sin objetivo indicado" never looks like the
/// console's own placeholder, and a trailing space shows.
pub fn quoted_text(value: &str) -> String {
    format!("\"{}\"", unambiguous_text(value).replace('"', "\\\""))
}

/// Characters that could hide or disguise text are shown as `\u{xxxx}`,
/// by Unicode general category rather than by a closed list: control
/// (Cc), format (Cf: bidi, zero-width, tags, BOM, soft hyphen...), line and
/// paragraph separators (Zl, Zp), private use (Co), unassigned (Cn), and
/// every space separator (Zs) other than U+0020 (no-break space, U+3000...).
/// Also variation selectors, the combining grapheme joiner, the Hangul
/// fillers and the blank Braille pattern, which render as nothing.
pub(crate) fn is_hidden(character: char) -> bool {
    use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
    let by_category = match character.general_category() {
        GeneralCategory::Control
        | GeneralCategory::Format
        | GeneralCategory::LineSeparator
        | GeneralCategory::ParagraphSeparator
        | GeneralCategory::PrivateUse
        | GeneralCategory::Unassigned
        | GeneralCategory::Surrogate => true,
        GeneralCategory::SpaceSeparator => character != ' ',
        _ => false,
    };
    by_category
        || matches!(
            character,
            '\u{fe00}'..='\u{fe0f}'
                | '\u{e0100}'..='\u{e01ef}'
                | '\u{180b}'..='\u{180d}'
                | '\u{180f}'
                | '\u{034f}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{3164}'
                | '\u{ffa0}'
                | '\u{2800}'
        )
}

fn push_inert(safe: &mut String, character: char) {
    if is_hidden(character) {
        safe.push_str(&format!("\\u{{{:04x}}}", character as u32));
    } else {
        safe.push(character);
    }
}

pub fn visible_target(facts: &ReceiptFacts) -> ShownText {
    if !facts.legible {
        return ShownText::placeholder(Placeholder::NotShown);
    }
    facts
        .target
        .clone()
        .filter(|target| !target.is_empty())
        .map(|target| ShownText::text(plain_text(&target)))
        .unwrap_or_else(|| ShownText::placeholder(Placeholder::NoTarget))
}

pub fn visible_wanted(facts: &ReceiptFacts) -> ShownText {
    if !facts.legible || facts.wanted.is_empty() {
        ShownText::placeholder(Placeholder::NotShown)
    } else {
        ShownText::text(plain_text(&facts.wanted))
    }
}

/// The configured name, or the agent's place among the agents of this read
/// (the page says "Agent N").
pub fn agent_label(agent_id: Uuid, names: &HashMap<Uuid, String>, order: &[Uuid]) -> AgentView {
    if let Some(name) = names.get(&agent_id) {
        return AgentView {
            nombre: Some(name.clone()),
            numero: None,
        };
    }
    AgentView {
        nombre: None,
        numero: order
            .iter()
            .position(|agent| *agent == agent_id)
            .and_then(|index| u32::try_from(index + 1).ok()),
    }
}

#[derive(Debug)]
pub enum NamesError {
    TooLarge,
    Invalid,
}

impl std::fmt::Display for NamesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("el archivo de nombres de agentes no se puede usar")
    }
}

impl std::error::Error for NamesError {}

/// `agent-uuid = nombre`. Blank lines and `#` comments are ignored.
/// A name that is itself a UUID or a long hex string is refused.
pub fn parse_agent_names(document: &str) -> Result<HashMap<Uuid, String>, NamesError> {
    if document.len() > 1_048_576 {
        return Err(NamesError::TooLarge);
    }
    let mut names = HashMap::new();
    for raw in document.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id, name)) = line.split_once('=') else {
            return Err(NamesError::Invalid);
        };
        let id = Uuid::parse_str(id.trim()).map_err(|_| NamesError::Invalid)?;
        if id.is_nil() {
            return Err(NamesError::Invalid);
        }
        let name = name.trim();
        if !acceptable_agent_name(name) || names.insert(id, name.to_owned()).is_some() {
            return Err(NamesError::Invalid);
        }
    }
    Ok(names)
}

fn acceptable_agent_name(name: &str) -> bool {
    (1..=80).contains(&name.chars().count())
        && !name.chars().any(char::is_control)
        && Uuid::parse_str(name).is_err()
        && !(name.len() >= 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug, Clone)]
pub struct ListRequest {
    pub situation: Option<Situation>,
    pub from: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawQuery {
    pub situacion: Option<String>,
    pub desde: Option<String>,
    pub hasta: Option<String>,
    pub pagina: Option<u32>,
}

pub fn prepare_query(raw: RawQuery) -> Result<ListRequest, ()> {
    prepare_query_at(raw, None)
}

/// `numero` is the 1-based place in the filtered list. The page parameter is ignored.
pub fn prepare_detail_query(raw: RawQuery, numero: u64) -> Result<ListRequest, ()> {
    if numero == 0 || numero > u64::from(MAX_OFFSET) + 1 {
        return Err(());
    }
    prepare_query_at(raw, Some(numero - 1))
}

fn prepare_query_at(raw: RawQuery, detail_offset: Option<u64>) -> Result<ListRequest, ()> {
    let raw_situation = raw
        .situacion
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let situation = match raw_situation {
        None => None,
        Some(value) => Some(Situation::parse(value).ok_or(())?),
    };
    let from = raw.desde.as_deref().map(parse_day).transpose()?;
    let until_day = raw.hasta.as_deref().map(parse_day).transpose()?;
    if from.is_some() != until_day.is_some() {
        return Err(());
    }
    let until = if let (Some(from), Some(until_day)) = (from, until_day) {
        if until_day < from || until_day - from > Duration::days(90) {
            return Err(());
        }
        Some(until_day.checked_add(Duration::days(1)).ok_or(())?)
    } else {
        None
    };
    let (offset, limit) = if let Some(offset) = detail_offset {
        (u32::try_from(offset).map_err(|_| ())?, 1)
    } else {
        let page = raw.pagina.unwrap_or(1);
        if page == 0 {
            return Err(());
        }
        let offset = u64::from(page - 1) * u64::from(PAGE_SIZE);
        if offset > u64::from(MAX_OFFSET) {
            return Err(());
        }
        (u32::try_from(offset).map_err(|_| ())?, PAGE_SIZE)
    };
    Ok(ListRequest {
        situation,
        from,
        until,
        offset,
        limit,
    })
}

pub const PAGE_SIZE: u32 = 25;
pub const MAX_OFFSET: u32 = 10_000;

fn parse_day(value: &str) -> Result<OffsetDateTime, ()> {
    if value.len() != 10 || value.as_bytes()[4] != b'-' || value.as_bytes()[7] != b'-' {
        return Err(());
    }
    let year: i32 = value[0..4].parse().map_err(|_| ())?;
    let month: u8 = value[5..7].parse().map_err(|_| ())?;
    let day: u8 = value[8..10].parse().map_err(|_| ())?;
    let date = Date::from_calendar_date(year, Month::try_from(month).map_err(|_| ())?, day)
        .map_err(|_| ())?;
    Ok(date.midnight().assume_utc())
}

pub fn parse_journal_timestamp(value: &str) -> Result<OffsetDateTime, ()> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PageWindow {
    pub page: u32,
    pub pages: u32,
}

pub fn page_window(total: i64, offset: u32) -> PageWindow {
    let pages = if total <= 0 {
        1
    } else {
        let total = u32::try_from(total).unwrap_or(u32::MAX);
        total.div_ceil(PAGE_SIZE).max(1)
    };
    let page = offset / PAGE_SIZE + 1;
    PageWindow { page, pages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::{
        Action, AgentId, AgentKeyPair, Authority, Decision, Evidence, EvidenceAttesterKey,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn moment() -> OffsetDateTime {
        OffsetDateTime::parse("2026-10-24T12:34:56Z", &Rfc3339).unwrap()
    }

    fn facts(
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        attested: Option<AttestedExecution>,
        reason: Option<NotDispatchedReason>,
    ) -> ReceiptFacts {
        ReceiptFacts {
            created_at: moment(),
            updated_at: moment(),
            agent_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            authorization,
            execution,
            attested,
            reason,
            legible: true,
            wanted: "escribir_archivo".into(),
            target: Some("informe-trimestral".into()),
        }
    }

    #[test]
    fn agent_text_cannot_hide_behind_bidi_or_control_characters() {
        assert_eq!(
            plain_text("informe\u{202e}fdp.exe"),
            "informe\\u{202e}fdp.exe"
        );
        assert_eq!(plain_text("a\nb\u{0007}"), "a\\u{000a}b\\u{0007}");
        assert_eq!(plain_text("informe-trimestral"), "informe-trimestral");
    }

    /// The console sends each instant as RFC 3339 in UTC, seconds kept; the
    /// page words it (local time with its offset, and UTC beside it; see
    /// `tests-js/hora.test.mjs`).
    #[test]
    fn instants_are_sent_as_rfc3339_utc_for_the_page_to_word() {
        let text = crate::codigos::utc_instant(moment());
        assert_eq!(text, "2026-10-24T12:34:56Z");
        let offset = OffsetDateTime::parse("2026-10-24T09:34:56-03:00", &Rfc3339).unwrap();
        assert_eq!(crate::codigos::utc_instant(offset), "2026-10-24T12:34:56Z");
    }

    #[test]
    fn awaiting_approval_is_named_in_plain_language() {
        let pending = facts(
            AuthorizationStatus::RequiresApproval,
            ExecutionStatus::NotDispatched,
            Some(AttestedExecution::AwaitingApproval),
            None,
        );
        assert_eq!(situation(&pending), Situation::AwaitingApproval);
        assert_eq!(situation(&pending).code(), "awaiting_approval");
        assert_eq!(story(&pending), Story::AwaitingApproval);
        // The page says it in plain words, never the code.
        let es = crate::tests_i18n::es;
        assert_eq!(es("situation.awaiting_approval"), "pendiente de aprobación");
        assert!(es("story.awaiting_approval").contains("pendiente de aprobación"));
        assert!(!es("situation.awaiting_approval").contains("awaiting_approval"));
    }

    #[test]
    fn a_hold_without_the_signed_word_is_still_pending() {
        let legacy = facts(
            AuthorizationStatus::RequiresApproval,
            ExecutionStatus::NotDispatched,
            None,
            None,
        );
        assert_eq!(situation(&legacy), Situation::AwaitingApproval);
    }

    #[test]
    fn the_history_words_follow_the_journal() {
        let cases = [
            (
                facts(
                    AuthorizationStatus::Allowed,
                    ExecutionStatus::Authorized,
                    None,
                    None,
                ),
                Situation::Permitted,
            ),
            (
                facts(
                    AuthorizationStatus::Denied,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    None,
                ),
                Situation::Denied,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::ApprovedPendingDispatch,
                    None,
                    None,
                ),
                Situation::ApprovedPendingExecution,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::Executed,
                    Some(AttestedExecution::Executed),
                    None,
                ),
                Situation::Approved,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovalRejected),
                ),
                Situation::Rejected,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovalExpired),
                ),
                Situation::Expired,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovedClaimExpired),
                ),
                Situation::Expired,
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::DispatchRefused),
                ),
                Situation::NotExecuted,
            ),
        ];
        for (facts, expected) in cases {
            assert_eq!(situation(&facts), expected);
        }
    }

    #[test]
    fn rejection_wins_over_a_stale_awaiting_attestation() {
        let rejected = facts(
            AuthorizationStatus::RequiresApproval,
            ExecutionStatus::NotDispatched,
            Some(AttestedExecution::AwaitingApproval),
            Some(NotDispatchedReason::ApprovalRejected),
        );
        assert_eq!(situation(&rejected), Situation::Rejected);
    }

    #[test]
    fn an_unreadable_receipt_hides_the_target() {
        let mut broken = facts(
            AuthorizationStatus::Allowed,
            ExecutionStatus::Authorized,
            None,
            None,
        );
        broken.legible = false;
        broken.target = Some("no-mostrar".into());
        broken.wanted = "escribir_archivo".into();
        assert_eq!(situation(&broken), Situation::Unreadable);
        let hidden = ShownText::placeholder(Placeholder::NotShown);
        assert_eq!(visible_target(&broken), hidden);
        assert_eq!(visible_wanted(&broken), hidden);
    }

    #[test]
    fn public_action_keeps_the_target_and_drops_parameters() {
        let (json, _agent, _request) = signed_evidence("informe-trimestral");
        assert!(json.contains("parameter-secret"));
        assert!(json.contains("context-secret"));
        let action = public_action(&json, None).unwrap();
        assert_eq!(action.wanted, "escribir_archivo");
        assert_eq!(action.target.as_deref(), Some("informe-trimestral"));
        let rendered = format!("{} {}", action.wanted, action.target.unwrap_or_default());
        assert!(!rendered.contains("parameter-secret"));
        assert!(!rendered.contains("context-secret"));
    }

    #[test]
    fn a_tampered_target_is_not_shown() {
        let (json, _, _) = signed_evidence("informe-trimestral");
        let tampered = json.replace("informe-trimestral", "objetivo-alterado");
        assert!(tampered.contains("objetivo-alterado"));
        assert!(public_action(&tampered, None).is_err());
    }

    fn columns(evidence_json: String, agent_id: Uuid, request_id: Uuid) -> JournalColumns {
        JournalColumns {
            created_at: moment(),
            updated_at: moment(),
            agent_id,
            request_id,
            authorization: AuthorizationStatus::Allowed,
            execution: ExecutionStatus::Executed,
            attested: Some(AttestedExecution::Executed),
            reason: None,
            evidence_json,
        }
    }

    fn pin(secret: &[u8; 32]) -> VerifiedPublicKey {
        EvidenceAttesterKey::from_secret_bytes(secret)
            .public_key()
            .unwrap()
    }

    #[test]
    fn with_pins_a_receipt_signed_by_another_attester_is_unreadable_and_the_rest_is_shown() {
        let pins = [pin(&[0x32; 32])];
        let (good, agent, request) = signed_evidence("informe-trimestral");
        let (foreign, foreign_agent, foreign_request) =
            signed_evidence_by("informe-ajeno", &[0x33; 32], &"cd".repeat(32));
        // The foreign receipt's integrity hash checks out: only its signer
        // is not one of the pins.
        assert!(public_action(&foreign, None).is_ok());
        let receipts: Vec<ReceiptFacts> = [
            columns(good.clone(), agent, request),
            columns(foreign, foreign_agent, foreign_request),
            columns(good, agent, request),
        ]
        .into_iter()
        .map(|row| facts_from_columns(row, Some(&pins)))
        .collect();
        assert_eq!(receipts.len(), 3);
        assert!(receipts[0].legible && receipts[2].legible);
        assert_eq!(receipts[0].target.as_deref(), Some("informe-trimestral"));
        assert!(!receipts[1].legible);
        assert_eq!(situation(&receipts[1]), Situation::Unreadable);
        let hidden = ShownText::placeholder(Placeholder::NotShown);
        assert_eq!(visible_target(&receipts[1]), hidden);
        assert_eq!(visible_wanted(&receipts[1]), hidden);
        assert_eq!(receipts[1].target, None);
        assert_eq!(situation(&receipts[0]), Situation::Permitted);
    }

    #[test]
    fn with_pins_a_receipt_of_an_earlier_policy_stays_readable() {
        // Signed by the pinned attester under a policy whose digest is not
        // the one the console has loaded: the history does not require the
        // current policy.
        let pins = [pin(&[0x32; 32])];
        let (earlier, agent, request) =
            signed_evidence_by("informe-viejo", &[0x32; 32], &"ab".repeat(32));
        let facts = facts_from_columns(columns(earlier, agent, request), Some(&pins));
        assert!(facts.legible);
        assert_eq!(facts.target.as_deref(), Some("informe-viejo"));
        assert_eq!(situation(&facts), Situation::Permitted);
    }

    #[test]
    fn without_pins_the_history_checks_the_integrity_hash_only() {
        let (foreign, agent, request) =
            signed_evidence_by("informe-ajeno", &[0x33; 32], &"cd".repeat(32));
        let facts = facts_from_columns(columns(foreign.clone(), agent, request), None);
        assert!(facts.legible);
        assert_eq!(facts.target.as_deref(), Some("informe-ajeno"));
        // A tampered receipt is still unreadable, without failing the read.
        let tampered = foreign.replace("informe-ajeno", "informe-otro");
        let facts = facts_from_columns(columns(tampered, agent, request), None);
        assert!(!facts.legible);
        assert_eq!(facts.target, None);
    }

    #[test]
    fn agent_names_replace_ordinals_and_refuse_technical_names() {
        let named = Uuid::from_u128(2);
        let other = Uuid::from_u128(9);
        let names = parse_agent_names(&format!("{named} = lector\n")).unwrap();
        let order = [other, named];
        assert_eq!(
            agent_label(named, &names, &order),
            AgentView {
                nombre: Some("lector".into()),
                numero: None
            }
        );
        // The number; the page says "Agente 1", "Agent 1"...
        assert_eq!(
            agent_label(other, &names, &order),
            AgentView {
                nombre: None,
                numero: Some(1)
            }
        );
        assert_eq!(
            agent_label(Uuid::from_u128(77), &names, &order),
            AgentView {
                nombre: None,
                numero: None
            }
        );
        assert!(parse_agent_names(&format!("{named} = {named}\n")).is_err());
        assert!(parse_agent_names(&format!("{named} = {}\n", "ab".repeat(16))).is_err());
        assert!(parse_agent_names(&format!("{named} = lector\n{named} = otro\n")).is_err());
    }

    #[test]
    fn day_filters_are_calendar_dates() {
        let query = prepare_query(RawQuery {
            situacion: Some("pendiente de aprobación".into()),
            desde: Some("2026-10-01".into()),
            hasta: Some("2026-10-24".into()),
            pagina: Some(2),
        })
        .unwrap();
        assert_eq!(query.situation, Some(Situation::AwaitingApproval));
        assert_eq!(query.offset, 25);
        assert_eq!(query.limit, 25);
        // Not filters: the unreadable situation, in either form, and words
        // that are neither a code nor the former phrase.
        for value in [
            "unreadable",
            "no se puede leer",
            "awaiting approval",
            "AWAITING_APPROVAL",
        ] {
            assert!(
                prepare_query(RawQuery {
                    situacion: Some(value.into()),
                    desde: None,
                    hasta: None,
                    pagina: None,
                })
                .is_err(),
                "{value}"
            );
        }
        assert!(
            prepare_query(RawQuery {
                situacion: None,
                desde: Some("2026-10-24T00:00:00Z".into()),
                hasta: Some("2026-10-25T00:00:00Z".into()),
                pagina: None,
            })
            .is_err()
        );
        assert!(
            prepare_query(RawQuery {
                situacion: None,
                desde: Some("2026-01-01".into()),
                hasta: None,
                pagina: None,
            })
            .is_err()
        );
        assert!(
            prepare_query(RawQuery {
                situacion: None,
                desde: Some("2026-01-01".into()),
                hasta: Some("2026-05-01".into()),
                pagina: None,
            })
            .is_err()
        );
    }

    /// The filter takes the code the page sends now and, for a page or a
    /// link from before codes, the Spanish phrase: each gives the same
    /// situation, for every situation that can be filtered.
    #[test]
    fn the_situation_filter_takes_the_code_and_the_former_phrase() {
        let filterable: Vec<Situation> = Situation::ALL
            .iter()
            .copied()
            .filter(|situation| *situation != Situation::Unreadable)
            .collect();
        assert_eq!(filterable.len(), 8);
        for situation in filterable {
            assert_eq!(Situation::parse(situation.code()), Some(situation));
            let phrase = situation.legacy_phrase().unwrap();
            assert_eq!(Situation::parse(phrase), Some(situation), "{phrase}");
            // The former phrase is what the Spanish catalog shows.
            assert_eq!(
                crate::tests_i18n::es(&format!("situation.{}", situation.code())),
                phrase
            );
        }
        assert_eq!(
            Situation::parse("pendiente de aprobación"),
            Situation::parse("awaiting_approval")
        );
        assert_eq!(Situation::parse("unreadable"), None);
    }

    fn signed_evidence(target: &str) -> (String, Uuid, Uuid) {
        signed_evidence_by(target, &[0x32; 32], &"cd".repeat(32))
    }

    fn signed_evidence_by(
        target: &str,
        attester_secret: &[u8; 32],
        policy_digest: &str,
    ) -> (String, Uuid, Uuid) {
        let agent_key = AgentKeyPair::from_secret_bytes(&[0x31; 32]);
        let agent = agent_key.identity(AgentId::new());
        let agent_id = *agent.id.as_uuid();
        let authority = Authority::new(
            agent.id.clone(),
            "consola-test",
            vec!["archivo:escribir".into()],
        )
        .with_constraint("tenant_id", Uuid::from_u128(1).to_string());
        let action = Action::new(
            "escribir_archivo",
            Some(target.into()),
            json!({"value": "parameter-secret"}),
        )
        .unwrap()
        .with_capability("archivo:escribir");
        let mut context = BTreeMap::new();
        context.insert("nota".into(), json!("context-secret"));
        let mut evidence = Evidence::new_with_context(
            Uuid::from_u128(7),
            agent,
            authority,
            action,
            Decision::allow("motivo-interno", praetore_core::DecidedBy::rule("regla")),
            None,
            context,
        )
        .unwrap();
        evidence
            .bind_policy_digest(policy_digest.to_owned())
            .unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(attester_secret);
        evidence.sign(&attester).unwrap();
        let json = evidence.to_json().unwrap();
        (json, agent_id, evidence.request_id)
    }
}
