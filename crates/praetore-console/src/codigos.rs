//! Stable codes the console sends to its page instead of sentences.
//!
//! The page turns each code into words with its catalogs
//! (`ui/i18n/{es,en,pt}.json`): the server never chooses a language, and
//! nothing it signs, records or exports depends on one. Each enum is
//! declared through [`codes!`], which also lists every variant in `ALL`, so
//! the catalog test walks the codes from here and not from a copied list.

/// Declares a code enum: each variant, its code (English, snake_case) and,
/// in brackets, the parameters its catalog text uses (`{limite}`...).
macro_rules! codes {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $code:literal $([$($param:literal),*])? ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every variant, in declaration order.
            #[allow(dead_code)]
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }

            /// Names of the parameters sent with this code.
            #[allow(dead_code)]
            pub fn params(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$($($param),*)?]),+
                }
            }

            #[allow(dead_code)]
            pub fn from_code(value: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|item| item.code() == value)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.code())
            }
        }
    };
}

codes! {
    /// What a past receipt was, and what an inbox request is. Catalog key
    /// `situation.<code>`.
    pub enum Situation {
        Permitted => "permitted",
        Denied => "denied",
        Approved => "approved",
        Rejected => "rejected",
        Expired => "expired",
        AwaitingApproval => "awaiting_approval",
        ApprovedPendingExecution => "approved_pending_execution",
        NotExecuted => "not_executed",
        Unreadable => "unreadable",
    }
}

codes! {
    /// The state an action leaves a request in, as the page shows it.
    /// Catalog key `situation.<code>`. `Unchanged` keeps the label the
    /// request already had.
    pub enum OutcomeState {
        Unchanged => "unchanged",
        Unconfirmed => "unconfirmed",
        Approved => "approved",
        ApprovedPendingExecution => "approved_pending_execution",
        Rejected => "rejected",
        Expired => "expired",
        NotExecuted => "not_executed",
    }
}

codes! {
    /// The plain account of one receipt. Catalog key `story.<code>`.
    pub enum Story {
        Unreadable => "unreadable",
        Denied => "denied",
        Rejected => "rejected",
        ExpiredAfterApproval => "expired_after_approval",
        ExpiredWithoutDecision => "expired_without_decision",
        AwaitingApproval => "awaiting_approval",
        ApprovedPendingExecution => "approved_pending_execution",
        PermittedExecuted => "permitted_executed",
        PermittedFailed => "permitted_failed",
        PermittedOutcomeUnknown => "permitted_outcome_unknown",
        PermittedDispatched => "permitted_dispatched",
        PermittedNotExecuted => "permitted_not_executed",
        PermittedNotYetExecuted => "permitted_not_yet_executed",
        ApprovedExecuted => "approved_executed",
        ApprovedFailed => "approved_failed",
        ApprovedOutcomeUnknown => "approved_outcome_unknown",
        ApprovedDispatched => "approved_dispatched",
        Approved => "approved",
        NotExecutedRefused => "not_executed_refused",
        NotExecuted => "not_executed",
    }
}

codes! {
    /// Standing notices of the page. Catalog key `notice.<code>`.
    pub enum Notice {
        /// History: a receipt of what happened, not a current authorization.
        ReceiptNotAuthorization => "receipt_not_authorization",
        /// Inbox: what each click does.
        InboxHowItWorks => "inbox_how_it_works",
    }
}

codes! {
    /// What the console shows in place of text it does not show. Catalog
    /// key `value.<code>`.
    pub enum Placeholder {
        /// The receipt does not check out, or carries no action.
        NotShown => "not_shown",
        /// The request names no target.
        NoTarget => "no_target",
    }
}

codes! {
    /// Messages: errors, refusals and the result of an action. Catalog key
    /// `message.<code>`.
    pub enum MessageCode {
        SessionRequired => "session_required",
        WrongHost => "wrong_host",
        BadQuery => "bad_query",
        JournalUnreadable => "journal_unreadable",
        ReceiptGone => "receipt_gone",
        InboxOff => "inbox_off",
        InboxTruncated => "inbox_truncated" ["limite"],
        ActionPageOnly => "action_page_only",
        RequestGone => "request_gone",
        ParametersNotShown => "parameters_not_shown",
        OutcomeUnknownCheckHistory => "outcome_unknown_check_history",
        OpeningPageOnly => "opening_page_only",
        OpeningUnreadable => "opening_unreadable",
        OpeningRefused => "opening_refused",
        SessionUnavailable => "session_unavailable",
        PackOff => "pack_off",
        PackPageOnly => "pack_page_only",
        PackPolicy => "pack_policy",
        PackAttesterPins => "pack_attester_pins",
        PackAttesterPinIsApproverKey => "pack_attester_pin_is_approver_key",
        PackAttesterPinUnused => "pack_attester_pin_unused" ["posicion"],
        PackAttesterPinsUnused => "pack_attester_pins_unused" ["posicion"],
        PackBusy => "pack_busy",
        PackJournal => "pack_journal",
        PackArchive => "pack_archive",
        PackExecutionPins => "pack_execution_pins",
        PackApproverPins => "pack_approver_pins",
        PackExecutionPinIsApproverKey => "pack_execution_pin_is_approver_key",
        PackApproverPinIsApproverSecret => "pack_approver_pin_is_approver_secret",
        PackOutcomeKeyMissing => "pack_outcome_key_missing",
        PackOutcomes => "pack_outcomes",
        PackOutcomesTooLarge => "pack_outcomes_too_large",
        EvidenceUnverified => "evidence_unverified",
        GatewayUnintelligible => "gateway_unintelligible",
        GatewayUnreachableNothingSigned => "gateway_unreachable_nothing_signed",
        ChallengeMismatch => "challenge_mismatch",
        SignFailed => "sign_failed",
        ApprovedNotYetExecuted => "approved_not_yet_executed",
        RejectedFinal => "rejected_final",
        GatewayUnreachableNoDecision => "gateway_unreachable_no_decision",
        DecisionUnconfirmed => "decision_unconfirmed",
        RequestNoLongerThere => "request_no_longer_there",
        AlreadyDecidedNothingSigned => "already_decided_nothing_signed",
        ApprovalWindowClosed => "approval_window_closed",
        NotAnApprover => "not_an_approver",
        GatewayBusyNothingSigned => "gateway_busy_nothing_signed",
        AlreadyDecidedNoOther => "already_decided_no_other",
        WindowClosedBeforeDecision => "window_closed_before_decision",
        DispatchRefusedClosed => "dispatch_refused_closed",
        SelfApprovalForbidden => "self_approval_forbidden",
        SignatureRefused => "signature_refused",
        NoApprovers => "no_approvers",
        DecisionRefused => "decision_refused",
        Executed => "executed",
        ExecutionFailed => "execution_failed",
        ExecutionOutcomeUnknown => "execution_outcome_unknown",
        GatewayAnsweredCheckHistory => "gateway_answered_check_history",
        DispatchRefused => "dispatch_refused",
        ExecutionFailedPartial => "execution_failed_partial",
        WindowClosedBeforeExecution => "window_closed_before_execution",
        NoLongerPendingExecution => "no_longer_pending_execution",
        StillApprovedRetryBusy => "still_approved_retry_busy",
        StillApprovedNotAnApprover => "still_approved_not_an_approver",
        StillApprovedRetryUnreachable => "still_approved_retry_unreachable",
        ExecutionUnconfirmed => "execution_unconfirmed",
    }
}

/// A message for the page: its code and, when the code has them, its
/// parameters. Serialized as `{"codigo": "...", "limite": 200}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ApiMessage {
    pub codigo: MessageCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limite: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posicion: Option<u32>,
}

impl ApiMessage {
    pub const fn new(codigo: MessageCode) -> Self {
        Self {
            codigo,
            limite: None,
            posicion: None,
        }
    }

    pub const fn with_limit(codigo: MessageCode, limite: u32) -> Self {
        Self {
            codigo,
            limite: Some(limite),
            posicion: None,
        }
    }

    pub const fn with_position(codigo: MessageCode, posicion: u32) -> Self {
        Self {
            codigo,
            limite: None,
            posicion: Some(posicion),
        }
    }

    /// The parameters this message carries, by name.
    #[allow(dead_code)]
    pub fn sent_params(&self) -> Vec<&'static str> {
        let mut sent = Vec::new();
        if self.limite.is_some() {
            sent.push("limite");
        }
        if self.posicion.is_some() {
            sent.push("posicion");
        }
        sent
    }
}

impl From<MessageCode> for ApiMessage {
    fn from(codigo: MessageCode) -> Self {
        Self::new(codigo)
    }
}

/// Text the agent chose (already made inert), or the code of what the
/// console shows in its place. Serialized as `{"texto": "..."}` or
/// `{"codigo": "not_shown"}`, so agent text never reads as a placeholder.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum ShownText {
    Text { texto: String },
    Placeholder { codigo: Placeholder },
}

impl ShownText {
    pub fn text(texto: String) -> Self {
        Self::Text { texto }
    }

    pub fn placeholder(codigo: Placeholder) -> Self {
        Self::Placeholder { codigo }
    }
}

/// Who asked: the configured name when there is one, otherwise the agent's
/// number in this read (the page says "Agent N"), or neither.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nombre: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub numero: Option<u32>,
}

/// An instant for the page: RFC 3339 in UTC. The page shows it in the
/// browser's local time with its offset, and in UTC beside it.
pub fn utc_instant(moment: time::OffsetDateTime) -> String {
    use time::format_description::well_known::Rfc3339;
    moment
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}
