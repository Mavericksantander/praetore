//! Plain-language reading of one journal receipt.
//!
//! The words an operator sees are decided here. Technical state names stay in
//! this module and are not the product face.

use praetore_core::Evidence;
use praetore_gateway::{
    AttestedExecution, AuthorizationStatus, ExecutionStatus, NotDispatchedReason,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::{Date, Duration, Month, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// What the console says a past receipt was. Not a current authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Situation {
    Permitted,
    Denied,
    Approved,
    Rejected,
    Expired,
    AwaitingApproval,
    ApprovedPendingExecution,
    NotExecuted,
    Unreadable,
}

impl Situation {
    /// The words on the screen.
    pub fn phrase(self) -> &'static str {
        match self {
            Self::Permitted => "permitido",
            Self::Denied => "denegado",
            Self::Approved => "aprobado",
            Self::Rejected => "rechazado",
            Self::Expired => "expirado",
            Self::AwaitingApproval => "pendiente de aprobación",
            Self::ApprovedPendingExecution => "aprobado, pendiente de ejecución",
            Self::NotExecuted => "no se ejecutó",
            Self::Unreadable => "no se puede leer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "permitido" => Self::Permitted,
            "denegado" => Self::Denied,
            "aprobado" => Self::Approved,
            "rechazado" => Self::Rejected,
            "expirado" => Self::Expired,
            "pendiente de aprobación" => Self::AwaitingApproval,
            "aprobado, pendiente de ejecución" => Self::ApprovedPendingExecution,
            "no se ejecutó" => Self::NotExecuted,
            _ => return None,
        })
    }
}

pub const NOTICE: &str = "Esto es un recibo de lo que ya ocurrió. No es una autorización vigente ni prueba de un efecto fuera de este registro.";

const MONTHS: [&str; 12] = [
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
];

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

pub fn facts_from_columns(columns: JournalColumns) -> Result<ReceiptFacts, ()> {
    let action = public_action(&columns.evidence_json)?;
    Ok(ReceiptFacts {
        created_at: columns.created_at,
        updated_at: columns.updated_at,
        agent_id: columns.agent_id,
        request_id: columns.request_id,
        authorization: columns.authorization,
        execution: columns.execution,
        attested: columns.attested,
        reason: columns.reason,
        legible: true,
        wanted: action.wanted,
        target: action.target,
    })
}

pub struct PublicAction {
    pub wanted: String,
    pub target: Option<String>,
}

/// Action type and target when the receipt still checks out.
/// Parameters, context, and the raw JSON are dropped.
pub fn public_action(evidence_json: &str) -> Result<PublicAction, ()> {
    let evidence = Evidence::from_json(evidence_json).map_err(|_| ())?;
    // `from_json` already refuses a receipt that does not check out. A second
    // check keeps a tampered target from being copied if that ever changes.
    if !evidence.verify_integrity() {
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

pub fn story(facts: &ReceiptFacts) -> &'static str {
    match situation(facts) {
        Situation::Unreadable => {
            "Este recibo no cuadra, así que no se muestra qué se pidió ni sobre qué."
        }
        Situation::Denied => "La decisión fue denegar. No se ejecutó.",
        Situation::Rejected => "Una persona lo rechazó. El rechazo es final y no se ejecutó.",
        Situation::Expired => match facts.reason {
            Some(NotDispatchedReason::ApprovedClaimExpired) => {
                "Se había aprobado, y la ventana cerró antes de ejecutarlo."
            }
            _ => "La ventana de aprobación cerró sin una decisión. No se ejecutó.",
        },
        Situation::AwaitingApproval => {
            "Está pendiente de aprobación. Todavía no hay una decisión de una persona."
        }
        Situation::ApprovedPendingExecution => {
            "Una persona lo aprobó y falta ejecutarlo. La aprobación no se reutiliza."
        }
        Situation::Permitted => match facts.execution {
            ExecutionStatus::Executed | ExecutionStatus::Confirmed => {
                "La decisión fue permitir, y el registro dice que se ejecutó."
            }
            ExecutionStatus::Failed => "La decisión fue permitir. La ejecución falló.",
            ExecutionStatus::OutcomeUnknown => {
                "La decisión fue permitir. No quedó claro si llegó a ocurrir."
            }
            ExecutionStatus::Dispatched => {
                "La decisión fue permitir. Se inició y no quedó cerrado qué ocurrió después."
            }
            ExecutionStatus::NotDispatched => "La decisión fue permitir. No se ejecutó.",
            ExecutionStatus::Authorized | ExecutionStatus::ApprovedPendingDispatch => {
                "La decisión fue permitir. El registro no dice que ya se haya ejecutado."
            }
        },
        Situation::Approved => match facts.execution {
            ExecutionStatus::Executed | ExecutionStatus::Confirmed => {
                "Una persona lo aprobó y el registro dice que se ejecutó."
            }
            ExecutionStatus::Failed => "Una persona lo aprobó. La ejecución falló.",
            ExecutionStatus::OutcomeUnknown => {
                "Una persona lo aprobó. No quedó claro si llegó a ocurrir."
            }
            ExecutionStatus::Dispatched => {
                "Una persona lo aprobó. Se inició y no quedó cerrado qué ocurrió después."
            }
            _ => "Una persona lo aprobó.",
        },
        Situation::NotExecuted => match facts.reason {
            Some(NotDispatchedReason::DispatchRefused) => {
                "No se ejecutó. El sistema se negó antes de tocar el objetivo."
            }
            _ => "No se ejecutó.",
        },
    }
}

pub fn readable_time(moment: OffsetDateTime) -> String {
    let moment = moment.to_offset(time::UtcOffset::UTC);
    let month = usize::from(u8::from(moment.month()) - 1);
    format!(
        "{} de {} de {}, {:02}:{:02} UTC",
        moment.day(),
        MONTHS[month],
        moment.year(),
        moment.hour(),
        moment.minute()
    )
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
/// Used in the approvals inbox, where two different signed actions must
/// never look the same.
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

/// Control, bidirectional and invisible characters (zero-width space,
/// BOM, word joiner, soft hyphen, line and paragraph separators) are shown
/// as `\u{xxxx}`.
fn push_inert(safe: &mut String, character: char) {
    let hidden = matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200b}'
            | '\u{feff}'
            | '\u{2060}'
            | '\u{00ad}'
            | '\u{2028}'
            | '\u{2029}'
    );
    if character.is_control() || hidden {
        safe.push_str(&format!("\\u{{{:04x}}}", character as u32));
    } else {
        safe.push(character);
    }
}

pub fn visible_target(facts: &ReceiptFacts) -> String {
    if !facts.legible {
        return "no se muestra".to_owned();
    }
    facts
        .target
        .clone()
        .filter(|target| !target.is_empty())
        .map(|target| plain_text(&target))
        .unwrap_or_else(|| "sin objetivo indicado".to_owned())
}

pub fn visible_wanted(facts: &ReceiptFacts) -> String {
    if !facts.legible || facts.wanted.is_empty() {
        "no se muestra".to_owned()
    } else {
        plain_text(&facts.wanted)
    }
}

pub fn agent_label(agent_id: Uuid, names: &HashMap<Uuid, String>, order: &[Uuid]) -> String {
    if let Some(name) = names.get(&agent_id) {
        return name.clone();
    }
    match order.iter().position(|agent| *agent == agent_id) {
        Some(index) => format!("Agente {}", index + 1),
        None => "Agente".to_owned(),
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

    #[test]
    fn dates_are_calendar_words_not_rfc3339() {
        let text = readable_time(moment());
        assert_eq!(text, "24 de octubre de 2026, 12:34 UTC");
        assert!(!text.contains("2026-10-24"));
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
        assert_eq!(situation(&pending).phrase(), "pendiente de aprobación");
        assert!(story(&pending).contains("pendiente de aprobación"));
        assert!(!situation(&pending).phrase().contains("awaiting_approval"));
    }

    #[test]
    fn a_hold_without_the_signed_word_is_still_pending() {
        let legacy = facts(
            AuthorizationStatus::RequiresApproval,
            ExecutionStatus::NotDispatched,
            None,
            None,
        );
        assert_eq!(situation(&legacy).phrase(), "pendiente de aprobación");
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
                "permitido",
            ),
            (
                facts(
                    AuthorizationStatus::Denied,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    None,
                ),
                "denegado",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::ApprovedPendingDispatch,
                    None,
                    None,
                ),
                "aprobado, pendiente de ejecución",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::Executed,
                    Some(AttestedExecution::Executed),
                    None,
                ),
                "aprobado",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovalRejected),
                ),
                "rechazado",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovalExpired),
                ),
                "expirado",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::ApprovedClaimExpired),
                ),
                "expirado",
            ),
            (
                facts(
                    AuthorizationStatus::RequiresApproval,
                    ExecutionStatus::NotDispatched,
                    Some(AttestedExecution::NotDispatched),
                    Some(NotDispatchedReason::DispatchRefused),
                ),
                "no se ejecutó",
            ),
        ];
        for (facts, phrase) in cases {
            assert_eq!(situation(&facts).phrase(), phrase);
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
        assert_eq!(situation(&rejected).phrase(), "rechazado");
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
        assert_eq!(situation(&broken).phrase(), "no se puede leer");
        assert_eq!(visible_target(&broken), "no se muestra");
        assert_eq!(visible_wanted(&broken), "no se muestra");
    }

    #[test]
    fn public_action_keeps_the_target_and_drops_parameters() {
        let (json, _agent, _request) = signed_evidence("informe-trimestral");
        assert!(json.contains("parameter-secret"));
        assert!(json.contains("context-secret"));
        let action = public_action(&json).unwrap();
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
        assert!(public_action(&tampered).is_err());
    }

    #[test]
    fn agent_names_replace_ordinals_and_refuse_technical_names() {
        let named = Uuid::from_u128(2);
        let other = Uuid::from_u128(9);
        let names = parse_agent_names(&format!("{named} = lector\n")).unwrap();
        let order = [other, named];
        assert_eq!(agent_label(named, &names, &order), "lector");
        assert_eq!(agent_label(other, &names, &order), "Agente 1");
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
        assert!(
            prepare_query(RawQuery {
                situacion: Some("awaiting_approval".into()),
                desde: None,
                hasta: None,
                pagina: None,
            })
            .is_err()
        );
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

    fn signed_evidence(target: &str) -> (String, Uuid, Uuid) {
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
        evidence.bind_policy_digest("cd".repeat(32)).unwrap();
        let attester = EvidenceAttesterKey::from_secret_bytes(&[0x32; 32]);
        evidence.sign(&attester).unwrap();
        let json = evidence.to_json().unwrap();
        (json, agent_id, evidence.request_id)
    }
}
