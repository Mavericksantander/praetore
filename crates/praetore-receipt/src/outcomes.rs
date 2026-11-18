//! A tenant's approval and execution records, as one JSONL file
//! (`approvals.jsonl` in the console's compliance package), and their
//! verification against the tenant's journal chain.
//!
//! Each line is one signed record, exactly as the gateway persisted it:
//!
//! ```text
//! {"schema_version":1,"human_decision":{...}}     a HumanApprovalDecision (approve or reject)
//! {"schema_version":1,"approval_expired":{...}}   an ApprovalExpiredReceipt
//! {"schema_version":1,"execution_receipt":{...}}  a GatewayReceipt (schema v1 to v5)
//! ```
//!
//! [`verify_outcomes`] checks every record with the code the gateway and
//! `praetore-verify receipt` use: a human decision against the challenge
//! derived from its journal receipt and a pinned approver key; an expiration
//! receipt and an execution receipt against a pinned execution key; and the
//! evidence embedded in an execution receipt against the journal's receipt
//! for the same request. Fail-closed: the first problem ends verification.
//! It shows what the gateway recorded; it never authorizes an action.

use crate::{
    ApprovalChallenge, ApprovalExpiredReceipt, AttestedExecution, AuthorizationStatus,
    ExecutionAttestationError, GatewayReceipt, HumanApprovalDecision, HumanApprovalOutcome,
    NotDispatchedReason, action_digest,
};
use praetore_core::{
    DecisionOutcome, Evidence, VerifiedPublicKey, journal_chain::MAX_CHAIN_ENTRIES,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// The `schema_version` of every line.
pub const OUTCOMES_SCHEMA_VERSION: u8 = 1;
/// Largest outcomes file: execution receipts embed their evidence and the
/// adapter output.
pub const MAX_OUTCOMES_BYTES: usize = 32 * 1024 * 1024;
/// Most lines: per request, one human decision or expiration and a few
/// execution receipts (awaiting approval, outcome unknown, final).
pub const MAX_OUTCOME_LINES: usize = 5 * MAX_CHAIN_ENTRIES;
/// Most execution or approver pins.
pub const MAX_OUTCOME_PINS: usize = 16;
/// The `schema_version` of a key pin file.
pub const KEY_PIN_SCHEMA_VERSION: u8 = 1;

/// One signed record of the outcomes file.
#[derive(Debug, Clone)]
pub enum Outcome {
    HumanDecision(HumanApprovalDecision),
    ApprovalExpired(ApprovalExpiredReceipt),
    ExecutionReceipt(Box<GatewayReceipt>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    human_decision: Option<HumanApprovalDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_expired: Option<ApprovalExpiredReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_receipt: Option<GatewayReceipt>,
}

impl Outcome {
    /// The record as one line of the outcomes file, newline included.
    pub fn to_line(&self) -> Result<String, OutcomeError> {
        let mut line = Line {
            schema_version: OUTCOMES_SCHEMA_VERSION,
            human_decision: None,
            approval_expired: None,
            execution_receipt: None,
        };
        match self {
            Self::HumanDecision(decision) => line.human_decision = Some(decision.clone()),
            Self::ApprovalExpired(receipt) => line.approval_expired = Some(receipt.clone()),
            Self::ExecutionReceipt(receipt) => {
                line.execution_receipt = Some(receipt.as_ref().clone());
            }
        }
        let mut text = serde_json::to_string(&line).map_err(|_| OutcomeError::TooLarge)?;
        text.push('\n');
        Ok(text)
    }

    fn parse(text: &str) -> Option<Self> {
        let value = praetore_core::canonical::parse_json_rejecting_duplicates(text).ok()?;
        let line: Line = serde_json::from_value(value).ok()?;
        if line.schema_version != OUTCOMES_SCHEMA_VERSION {
            return None;
        }
        match (
            line.human_decision,
            line.approval_expired,
            line.execution_receipt,
        ) {
            (Some(decision), None, None) => Some(Self::HumanDecision(decision)),
            (None, Some(receipt), None) => Some(Self::ApprovalExpired(receipt)),
            (None, None, Some(receipt)) => Some(Self::ExecutionReceipt(Box::new(receipt))),
            _ => None,
        }
    }

    /// The request the record belongs to: agent id and request id.
    fn request(&self) -> (Uuid, Uuid) {
        match self {
            Self::HumanDecision(decision) => {
                (decision.challenge.agent_id, decision.challenge.request_id)
            }
            Self::ApprovalExpired(receipt) => (receipt.agent_id, receipt.request_id),
            Self::ExecutionReceipt(receipt) => (
                *receipt.evidence.agent.id.as_uuid(),
                receipt.evidence.request_id,
            ),
        }
    }
}

/// The outcomes file for `outcomes`, in that order. Fails over
/// [`MAX_OUTCOME_LINES`] or [`MAX_OUTCOMES_BYTES`].
pub fn write_outcomes(outcomes: &[Outcome]) -> Result<String, OutcomeError> {
    if outcomes.len() > MAX_OUTCOME_LINES {
        return Err(OutcomeError::TooLarge);
    }
    let mut text = String::new();
    for outcome in outcomes {
        text.push_str(&outcome.to_line()?);
        if text.len() > MAX_OUTCOMES_BYTES {
            return Err(OutcomeError::TooLarge);
        }
    }
    Ok(text)
}

/// A pinned public key and the key id the records it signed name. The pin
/// file is the JSON document `praetore init` writes as `approver-pin.json`:
/// `{"schema_version":1,"key_id":"...","public_key_hex":"<64 lowercase hex>"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPin {
    pub key_id: String,
    pub public_key: VerifiedPublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPinFile {
    schema_version: u8,
    key_id: String,
    public_key_hex: String,
}

impl KeyPin {
    /// Parses a pin file (surrounding whitespace ignored).
    pub fn from_json(text: &str) -> Result<Self, OutcomeError> {
        let value = praetore_core::canonical::parse_json_rejecting_duplicates(text.trim())
            .map_err(|_| OutcomeError::InvalidPin)?;
        let file: KeyPinFile =
            serde_json::from_value(value).map_err(|_| OutcomeError::InvalidPin)?;
        let encoded = file.public_key_hex.as_str();
        if file.schema_version != KEY_PIN_SCHEMA_VERSION
            || file.key_id.is_empty()
            || file.key_id.len() > 256
            || file.key_id.trim() != file.key_id
            || encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(OutcomeError::InvalidPin);
        }
        let bytes = hex::decode(encoded).map_err(|_| OutcomeError::InvalidPin)?;
        let public_key =
            VerifiedPublicKey::from_bytes(&bytes).map_err(|_| OutcomeError::InvalidPin)?;
        Ok(Self {
            key_id: file.key_id,
            public_key,
        })
    }

    /// The pin file, re-encoded from the parsed key, newline included.
    pub fn to_json(&self) -> String {
        let file = KeyPinFile {
            schema_version: KEY_PIN_SCHEMA_VERSION,
            key_id: self.key_id.clone(),
            public_key_hex: hex::encode(self.public_key.as_bytes()),
        };
        let mut text = serde_json::to_string(&file).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// The keys the records are checked against.
#[derive(Debug, Clone, Copy)]
pub struct OutcomeKeys<'a> {
    /// The journal's attester pins: an execution receipt's evidence must be
    /// signed by one of them.
    pub evidence_attesters: &'a [VerifiedPublicKey],
    /// Gateway execution keys: they sign execution and expiration receipts.
    pub execution: &'a [KeyPin],
    /// Human approver keys: they sign approve and reject decisions. Pin
    /// only the approvers of the journal's tenant: unlike the gateway, which
    /// scopes each approver to a tenant, a pin here is not tied to one.
    pub approvers: &'a [KeyPin],
}

/// How many records of each kind the file has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeCounts {
    pub approvals: u64,
    pub rejections: u64,
    pub expirations: u64,
    pub execution_receipts: u64,
    /// Execution receipts by signed state (`executed`, `awaiting_approval`, ...).
    pub by_execution: BTreeMap<&'static str, u64>,
}

/// How a request the policy held for approval ended, read from the verified
/// records of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldOutcome {
    /// No decision, no expiration and no closing receipt in the file: still
    /// pending, or its window closed and the gateway has not recorded it yet.
    Pending,
    Rejected,
    /// The window closed without a decision (signed expiration receipt).
    Expired,
    /// Approved; no dispatch recorded yet.
    ApprovedPendingDispatch,
    /// Approved and executed (`executed` or `confirmed`).
    ApprovedExecuted,
    ApprovedFailed,
    /// Approved and dispatched; the result is not known yet.
    ApprovedOutcomeUnknown,
    /// Approved, then closed without dispatch (see `not_dispatched_reason`).
    ApprovedNotDispatched,
    /// Closed without dispatch and without a human decision (for example,
    /// the adapter refused it before any effect).
    NotDispatched,
}

impl HeldOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::ApprovedPendingDispatch => "approved_pending_dispatch",
            Self::ApprovedExecuted => "approved_executed",
            Self::ApprovedFailed => "approved_failed",
            Self::ApprovedOutcomeUnknown => "approved_outcome_unknown",
            Self::ApprovedNotDispatched => "approved_not_dispatched",
            Self::NotDispatched => "not_dispatched",
        }
    }
}

/// One request of the journal that the policy held for approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldRequest {
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub evidence_id: Uuid,
    pub outcome: HeldOutcome,
    /// The latest signed execution state (a final one over
    /// `awaiting_approval` and `outcome_unknown`), if any.
    pub execution: Option<AttestedExecution>,
    pub not_dispatched_reason: Option<NotDispatchedReason>,
}

/// Result of [`verify_outcomes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeReport {
    pub counts: OutcomeCounts,
    /// Every held request of the journal, in journal order.
    pub held: Vec<HeldRequest>,
    /// Positions of the execution pins that verified no record.
    pub unused_execution_pins: Vec<usize>,
    /// Positions of the approver pins that verified no record.
    pub unused_approver_pins: Vec<usize>,
}

/// Why the outcomes file was not accepted. `line` counts from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeError {
    TooLarge,
    InvalidPin,
    /// Two pins of the same role share a key id.
    DuplicatePin,
    Malformed {
        line: usize,
    },
    /// The record's request is not in the journal.
    UnknownRequest {
        line: usize,
    },
    /// The record is not bound to the journal's receipt for its request.
    EvidenceMismatch {
        line: usize,
    },
    /// No pin has the key id the record names.
    UnknownKey {
        line: usize,
    },
    /// The signature, or the content it signs (such as an execution's
    /// output digest), does not verify.
    InvalidSignature {
        line: usize,
    },
    /// The approver key is the requesting agent's.
    SelfApproval {
        line: usize,
    },
    /// A second human decision or expiration for one request, or a second
    /// execution receipt with the same signed state.
    Duplicate {
        line: usize,
    },
    /// The records of one request contradict each other (for example, an
    /// execution of a held request without an approve decision).
    Inconsistent {
        line: usize,
    },
}

impl OutcomeError {
    /// Stable code for `praetore-verify`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge => "OUTCOMES_TOO_LARGE",
            Self::InvalidPin => "INVALID_PIN",
            Self::DuplicatePin => "OUTCOME_PIN_DUPLICATE",
            Self::Malformed { .. } => "OUTCOME_MALFORMED",
            Self::UnknownRequest { .. } => "OUTCOME_UNKNOWN_REQUEST",
            Self::EvidenceMismatch { .. } => "OUTCOME_EVIDENCE_MISMATCH",
            Self::UnknownKey { .. } => "OUTCOME_KEY_UNKNOWN",
            Self::InvalidSignature { .. } => "OUTCOME_SIGNATURE_INVALID",
            Self::SelfApproval { .. } => "OUTCOME_SELF_APPROVAL",
            Self::Duplicate { .. } => "OUTCOME_DUPLICATE",
            Self::Inconsistent { .. } => "OUTCOME_INCONSISTENT",
        }
    }
}

impl std::fmt::Display for OutcomeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self {
            Self::TooLarge => return f.write_str("outcomes file too large"),
            Self::InvalidPin => return f.write_str("invalid key pin"),
            Self::DuplicatePin => return f.write_str("two pins share a key id"),
            Self::Malformed { .. } => "malformed record",
            Self::UnknownRequest { .. } => "request not in the journal",
            Self::EvidenceMismatch { .. } => "record not bound to the journal receipt",
            Self::UnknownKey { .. } => "no pin for the record's key id",
            Self::InvalidSignature { .. } => "signature or signed content does not verify",
            Self::SelfApproval { .. } => "the approver is the requesting agent",
            Self::Duplicate { .. } => "duplicate record",
            Self::Inconsistent { .. } => "records of one request contradict each other",
        };
        let (Self::Malformed { line }
        | Self::UnknownRequest { line }
        | Self::EvidenceMismatch { line }
        | Self::UnknownKey { line }
        | Self::InvalidSignature { line }
        | Self::SelfApproval { line }
        | Self::Duplicate { line }
        | Self::Inconsistent { line }) = self
        else {
            unreachable!()
        };
        write!(f, "line {line}: {what}")
    }
}

impl std::error::Error for OutcomeError {}

#[derive(Default)]
struct RequestRecords {
    /// Decision outcome (or `None` for an expiration) and its line.
    resolution: Option<(Option<HumanApprovalOutcome>, usize)>,
    /// Signed execution states, their reasons and lines.
    executions: Vec<(AttestedExecution, Option<NotDispatchedReason>, usize)>,
}

/// Verifies an outcomes file against the receipts of a verified journal
/// chain (from `praetore_core::journal_chain::verify_journal_receipts`).
/// An empty file verifies, with every held request [`HeldOutcome::Pending`].
pub fn verify_outcomes(
    text: &str,
    journal: &[Evidence],
    keys: &OutcomeKeys<'_>,
) -> Result<OutcomeReport, OutcomeError> {
    if text.len() > MAX_OUTCOMES_BYTES {
        return Err(OutcomeError::TooLarge);
    }
    for pins in [keys.execution, keys.approvers] {
        if pins.len() > MAX_OUTCOME_PINS {
            return Err(OutcomeError::InvalidPin);
        }
        for (index, pin) in pins.iter().enumerate() {
            if pins[..index].iter().any(|other| other.key_id == pin.key_id) {
                return Err(OutcomeError::DuplicatePin);
            }
        }
    }
    // A request is named by agent and request id; one that appears twice in
    // the journal cannot be told apart, so its records are refused.
    let mut requests: HashMap<(Uuid, Uuid), Option<&Evidence>> = HashMap::new();
    for evidence in journal {
        requests
            .entry((*evidence.agent.id.as_uuid(), evidence.request_id))
            .and_modify(|slot| *slot = None)
            .or_insert(Some(evidence));
    }
    let mut execution_used = vec![false; keys.execution.len()];
    let mut approver_used = vec![false; keys.approvers.len()];
    let mut records: HashMap<(Uuid, Uuid), RequestRecords> = HashMap::new();
    let mut counts = OutcomeCounts::default();
    let mut rest = text;
    let mut line = 0;
    while !rest.is_empty() {
        if line >= MAX_OUTCOME_LINES {
            return Err(OutcomeError::TooLarge);
        }
        let (current, tail) = rest
            .split_once('\n')
            .ok_or(OutcomeError::Malformed { line })?;
        rest = tail;
        if current.is_empty() || current.contains('\r') {
            return Err(OutcomeError::Malformed { line });
        }
        let outcome = Outcome::parse(current).ok_or(OutcomeError::Malformed { line })?;
        let request = outcome.request();
        let evidence = requests
            .get(&request)
            .copied()
            .flatten()
            .ok_or(OutcomeError::UnknownRequest { line })?;
        let entry = records.entry(request).or_default();
        match &outcome {
            Outcome::HumanDecision(decision) => {
                let expected = action_digest(&evidence.action)
                    .ok()
                    .and_then(|digest| ApprovalChallenge::from_evidence(evidence, &digest).ok());
                if evidence.decision.outcome != DecisionOutcome::RequireApproval
                    || expected.as_ref() != Some(&decision.challenge)
                {
                    return Err(OutcomeError::EvidenceMismatch { line });
                }
                let index = find_pin(keys.approvers, &decision.approver_key_id)
                    .ok_or(OutcomeError::UnknownKey { line })?;
                let pin = &keys.approvers[index].public_key;
                decision
                    .verify_signature(&decision.approver_key_id, pin)
                    .map_err(|_| OutcomeError::InvalidSignature { line })?;
                if decision.is_self_approval(pin, evidence) {
                    return Err(OutcomeError::SelfApproval { line });
                }
                approver_used[index] = true;
                if entry.resolution.is_some() {
                    return Err(OutcomeError::Duplicate { line });
                }
                entry.resolution = Some((Some(decision.outcome), line));
                match decision.outcome {
                    HumanApprovalOutcome::Approve => counts.approvals += 1,
                    HumanApprovalOutcome::Reject => counts.rejections += 1,
                }
            }
            Outcome::ApprovalExpired(receipt) => {
                let index = find_pin(keys.execution, &receipt.gateway_key_id)
                    .ok_or(OutcomeError::UnknownKey { line })?;
                receipt
                    .verify(
                        evidence,
                        &keys.execution[index].public_key,
                        &keys.execution[index].key_id,
                    )
                    .map_err(|error| match error {
                        ExecutionAttestationError::InvalidSignature => {
                            OutcomeError::InvalidSignature { line }
                        }
                        _ => OutcomeError::EvidenceMismatch { line },
                    })?;
                execution_used[index] = true;
                if entry.resolution.is_some() {
                    return Err(OutcomeError::Duplicate { line });
                }
                entry.resolution = Some((None, line));
                counts.expirations += 1;
            }
            Outcome::ExecutionReceipt(receipt) => {
                // The embedded evidence is the journal's, field for field.
                if serde_json::to_value(&receipt.evidence).ok()
                    != serde_json::to_value(evidence).ok()
                {
                    return Err(OutcomeError::EvidenceMismatch { line });
                }
                let attestation = &receipt.execution_attestation;
                let index = find_pin(keys.execution, &attestation.key_id)
                    .ok_or(OutcomeError::UnknownKey { line })?;
                let pin = &keys.execution[index];
                let mut result = Err(OutcomeError::InvalidSignature { line });
                for attester in keys.evidence_attesters {
                    match receipt.verify_execution_attestation(
                        &pin.public_key,
                        &pin.key_id,
                        attester,
                    ) {
                        Ok(()) => {
                            result = Ok(());
                            break;
                        }
                        // Another attester pin may have signed the evidence.
                        Err(ExecutionAttestationError::InvalidEvidenceSignature) => {}
                        // The signature, or what it signs (the output digest,
                        // the binding to the evidence), does not verify.
                        Err(_) => break,
                    }
                }
                result?;
                execution_used[index] = true;
                // One receipt per signed state and reason, as the database's
                // unique key: before migration 0022 a held request had a
                // `not_dispatched` receipt without a reason (pending) and
                // then, when closed, a second one with its reason.
                if entry.executions.iter().any(|(execution, reason, _)| {
                    *execution == receipt.execution && *reason == attestation.not_dispatched_reason
                }) {
                    return Err(OutcomeError::Duplicate { line });
                }
                entry
                    .executions
                    .push((receipt.execution, attestation.not_dispatched_reason, line));
                counts.execution_receipts += 1;
                *counts
                    .by_execution
                    .entry(receipt.execution.as_str())
                    .or_default() += 1;
            }
        }
        line += 1;
    }
    let mut held = Vec::new();
    for evidence in journal {
        let request = (*evidence.agent.id.as_uuid(), evidence.request_id);
        let entry = records.remove(&request).unwrap_or_default();
        check_consistency(evidence, &entry)?;
        if evidence.decision.outcome == DecisionOutcome::RequireApproval {
            held.push(held_request(evidence, &entry));
        }
    }
    Ok(OutcomeReport {
        counts,
        held,
        unused_execution_pins: unused(&execution_used),
        unused_approver_pins: unused(&approver_used),
    })
}

fn find_pin(pins: &[KeyPin], key_id: &str) -> Option<usize> {
    pins.iter().position(|pin| pin.key_id == key_id)
}

fn unused(used: &[bool]) -> Vec<usize> {
    used.iter()
        .enumerate()
        .filter(|(_, used)| !**used)
        .map(|(index, _)| index)
        .collect()
}

/// The records of one request must tell one story: a held request that was
/// dispatched was approved, one closed as rejected has a reject decision.
fn check_consistency(evidence: &Evidence, entry: &RequestRecords) -> Result<(), OutcomeError> {
    let resolution = entry.resolution.map(|(resolution, _)| resolution);
    for &(execution, reason, line) in &entry.executions {
        let held = evidence.decision.outcome == DecisionOutcome::RequireApproval;
        let approved = resolution == Some(Some(HumanApprovalOutcome::Approve));
        let consistent = match (execution, reason) {
            (
                AttestedExecution::Executed
                | AttestedExecution::Confirmed
                | AttestedExecution::Failed
                | AttestedExecution::OutcomeUnknown,
                _,
            ) => !held || approved,
            (_, Some(NotDispatchedReason::ApprovalRejected)) => {
                resolution == Some(Some(HumanApprovalOutcome::Reject))
            }
            // Both close an approved request that was never claimed.
            (
                _,
                Some(
                    NotDispatchedReason::ApprovedClaimExpired
                    | NotDispatchedReason::DispatchFailed
                    | NotDispatchedReason::CrashRecovered,
                ),
            ) => approved,
            // Receipts signed before approved_claim_expired existed also
            // used approval_expired for an approval claimed too late.
            (_, Some(NotDispatchedReason::ApprovalExpired)) => approved || resolution == Some(None),
            _ => true,
        };
        if !consistent {
            return Err(OutcomeError::Inconsistent { line });
        }
    }
    if resolution.is_some() && evidence.decision.outcome != DecisionOutcome::RequireApproval {
        let line = entry.resolution.map_or(0, |(_, line)| line);
        return Err(OutcomeError::Inconsistent { line });
    }
    Ok(())
}

fn held_request(evidence: &Evidence, entry: &RequestRecords) -> HeldRequest {
    // A final state over a non-final one: the pending receipt stays in the
    // file after the request was approved and executed. A pending receipt
    // is `awaiting_approval` (schema v5) or, before migration 0022, a held
    // request's `not_dispatched` without a reason; neither says the request
    // was closed. Line order only breaks ties between equal ranks.
    let rank = |execution: AttestedExecution, reason: Option<NotDispatchedReason>| match (
        execution, reason,
    ) {
        (AttestedExecution::AwaitingApproval, _) | (AttestedExecution::NotDispatched, None) => 0,
        (AttestedExecution::OutcomeUnknown, _) => 1,
        _ => 2,
    };
    let latest = entry
        .executions
        .iter()
        .max_by_key(|(execution, reason, line)| (rank(*execution, *reason), *line))
        .map(|&(execution, reason, _)| (execution, reason));
    let closed = latest.is_some_and(|(execution, reason)| rank(execution, reason) > 0);
    let execution = latest.map(|(execution, _)| execution);
    let outcome = match (
        entry.resolution.map(|(resolution, _)| resolution),
        execution,
    ) {
        (Some(Some(HumanApprovalOutcome::Reject)), _) => HeldOutcome::Rejected,
        (Some(None), _) => HeldOutcome::Expired,
        (Some(Some(HumanApprovalOutcome::Approve)), execution) => match execution {
            Some(AttestedExecution::Executed | AttestedExecution::Confirmed) => {
                HeldOutcome::ApprovedExecuted
            }
            Some(AttestedExecution::Failed) => HeldOutcome::ApprovedFailed,
            Some(AttestedExecution::OutcomeUnknown) => HeldOutcome::ApprovedOutcomeUnknown,
            Some(AttestedExecution::NotDispatched) if closed => HeldOutcome::ApprovedNotDispatched,
            _ => HeldOutcome::ApprovedPendingDispatch,
        },
        (None, Some(AttestedExecution::NotDispatched)) if closed => HeldOutcome::NotDispatched,
        (None, _) => HeldOutcome::Pending,
    };
    HeldRequest {
        agent_id: *evidence.agent.id.as_uuid(),
        request_id: evidence.request_id,
        evidence_id: evidence.evidence_id,
        outcome,
        execution,
        not_dispatched_reason: latest.and_then(|(_, reason)| reason),
    }
}

/// The authorization a journal receipt implies, for building an execution
/// receipt from stored rows.
pub fn authorization_for(evidence: &Evidence) -> AuthorizationStatus {
    match evidence.decision.outcome {
        DecisionOutcome::Allow => AuthorizationStatus::Allowed,
        DecisionOutcome::RequireApproval => AuthorizationStatus::RequiresApproval,
        DecisionOutcome::Deny => AuthorizationStatus::Denied,
    }
}
