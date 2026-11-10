//! Gateway receipts and their signed execution attestations (schema v1 to
//! v4), with the signing and verification logic they need.
//!
//! This crate has no server dependencies so offline verifiers
//! (`praetore-verify`, the Python bindings) can use it. `praetore-gateway`
//! re-exports everything here.

use praetore_core::{
    Action, Authority, Evidence, PraetoreError,
    canonical::{canonicalize_json, is_canonical_signature_hex},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const ACTION_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ACTION_V1\0";
const EXECUTION_ATTESTATION_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_ATTESTATION_V1\0";
const OUTPUT_DIGEST_DOMAIN: &[u8] = b"PRAETORE_EXECUTION_OUTPUT_V1\0";

/// Computes the stable digest used to bind one normalized action to an
/// execution key. The canonical v1 encoding is domain separated from core
/// policy, request and evidence hashes.
pub fn action_digest(action: &Action) -> Result<String, PraetoreError> {
    let json = serde_json::to_string(action)
        .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))?;
    let canonical = canonicalize_json(&json)?;
    let mut hash = Sha256::new();
    hash.update(ACTION_DIGEST_DOMAIN);
    hash.update(canonical);
    Ok(hex::encode(hash.finalize()))
}

fn authority_tenant_id(authority: &Authority) -> Option<Uuid> {
    authority.tenant_id()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Allowed,
    RequiresApproval,
    Denied,
}

/// Final gateway-side state. `Dispatched` means the gateway durably committed
/// to invoking the adapter; it does not prove a remote system received a call.
///
/// `ApprovedPendingDispatch` exists only for `RequiresApproval`: a human
/// approved, and no dispatch has been claimed yet. Like `Authorized`, it is
/// intermediate and never appears in a [`GatewayReceipt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    NotDispatched,
    Authorized,
    ApprovedPendingDispatch,
    Dispatched,
    Executed,
    Confirmed,
    OutcomeUnknown,
    Failed,
}

/// Why an execution was closed as `NotDispatched` without ever reaching the
/// adapter. Signed into the closing [`ExecutionAttestation`]. All reasons
/// require `requires_approval`, except [`NotDispatchedReason::DispatchRefused`],
/// which may also close an `allowed` execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotDispatchedReason {
    /// The approval window closed before dispatch was claimed: either the
    /// approval was never decided (the signed expiration receipt exists), or
    /// it was approved and the claim came too late.
    ApprovalExpired,
    /// A human rejected the approval. Terminal: never dispatched.
    ApprovalRejected,
    /// Revalidation before the claim failed for a reason other than expiry.
    DispatchFailed,
    /// Reconciliation found the approval unclaimed after a restart.
    CrashRecovered,
    /// The adapter refused the action before any effect (its preflight
    /// check). Terminal: a held approval closed this way cannot be approved.
    DispatchRefused,
}

impl NotDispatchedReason {
    /// Whether this reason may be signed for an execution with the given
    /// authorization and execution state.
    pub fn applies_to(
        self,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
    ) -> bool {
        execution == ExecutionStatus::NotDispatched
            && match self {
                Self::DispatchRefused => matches!(
                    authorization,
                    AuthorizationStatus::Allowed | AuthorizationStatus::RequiresApproval
                ),
                _ => authorization == AuthorizationStatus::RequiresApproval,
            }
    }
}

/// Stable, machine-readable code an adapter (or the gateway) gives for a
/// refusal: 1 to 64 characters, `[a-z][a-z0-9_]*`. The constructor and
/// deserialization are the only ways to build one, so a signed code is
/// always well formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RefusalCode(String);

impl RefusalCode {
    pub const MAX_LEN: usize = 64;

    /// `None` unless `code` matches `[a-z][a-z0-9_]{0,63}`.
    pub fn new(code: &str) -> Option<Self> {
        let mut bytes = code.bytes();
        let valid = code.len() <= Self::MAX_LEN
            && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        valid.then(|| Self(code.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RefusalCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let code = String::deserialize(deserializer)?;
        Self::new(&code).ok_or_else(|| serde::de::Error::custom("invalid refusal code"))
    }
}

/// Signed classification of a `failed` execution (schema v4). Every new
/// `failed` attestation carries exactly one; see [`AttestedOutcome::Failed`].
///
/// Serialized as `{"class": "no_effect", "reason": "<code>"}` or
/// `{"class": "effect_failed"}`.
/// Deserialization is strict: an unknown class, a `no_effect` without a
/// valid reason, or any other field (including a `reason` on
/// `effect_failed`, or a `null` reason) is a payload error, not a
/// signature mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "class",
    rename_all = "snake_case",
    try_from = "RawExecutionFailure"
)]
pub enum ExecutionFailure {
    /// Refused before anything was touched at the target, with the refusal
    /// code. Only signed on positive proof: the adapter reported a refusal
    /// it guarantees changed nothing, or the gateway never invoked the
    /// adapter.
    NoEffect { reason: RefusalCode },
    /// The effect was attempted and did not complete; it may have left a
    /// residue (for example a temporary file, or a failure after opening or
    /// writing). Also the class whenever no effect cannot be proven
    /// (fail closed).
    EffectFailed,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawFailureClass {
    NoEffect,
    EffectFailed,
}

/// Wire form of [`ExecutionFailure`]. Serde ignores extra fields on an
/// internally tagged unit variant, so the shape is checked here instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecutionFailure {
    class: RawFailureClass,
    /// `None`: absent; `Some(None)`: an explicit `null`.
    #[serde(default, deserialize_with = "present_field")]
    reason: Option<Option<RefusalCode>>,
}

fn present_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

impl TryFrom<RawExecutionFailure> for ExecutionFailure {
    type Error = &'static str;

    fn try_from(raw: RawExecutionFailure) -> Result<Self, Self::Error> {
        match (raw.class, raw.reason) {
            (RawFailureClass::NoEffect, Some(Some(reason))) => Ok(Self::NoEffect { reason }),
            (RawFailureClass::EffectFailed, None) => Ok(Self::EffectFailed),
            (RawFailureClass::NoEffect, _) => Err("no_effect requires a reason"),
            (RawFailureClass::EffectFailed, Some(_)) => Err("effect_failed carries no reason"),
        }
    }
}

/// What a closing execution attestation states. Each variant carries exactly
/// the data its state may carry, so the signer cannot build a `failed`
/// attestation without its [`ExecutionFailure`], an output outside
/// `executed`/`confirmed`, or a [`NotDispatchedReason`] outside
/// `not_dispatched`. Intermediate states have no variant: they are never
/// attested.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestedOutcome {
    NotDispatched(Option<NotDispatchedReason>),
    Executed(Value),
    Confirmed(Value),
    OutcomeUnknown,
    Failed(ExecutionFailure),
}

impl AttestedOutcome {
    pub fn execution(&self) -> ExecutionStatus {
        match self {
            Self::NotDispatched(_) => ExecutionStatus::NotDispatched,
            Self::Executed(_) => ExecutionStatus::Executed,
            Self::Confirmed(_) => ExecutionStatus::Confirmed,
            Self::OutcomeUnknown => ExecutionStatus::OutcomeUnknown,
            Self::Failed(_) => ExecutionStatus::Failed,
        }
    }

    pub fn output(&self) -> Option<&Value> {
        match self {
            Self::Executed(output) | Self::Confirmed(output) => Some(output),
            _ => None,
        }
    }

    pub fn into_output(self) -> Option<Value> {
        match self {
            Self::Executed(output) | Self::Confirmed(output) => Some(output),
            _ => None,
        }
    }

    pub fn not_dispatched_reason(&self) -> Option<NotDispatchedReason> {
        match self {
            Self::NotDispatched(reason) => *reason,
            _ => None,
        }
    }

    pub fn failure(&self) -> Option<&ExecutionFailure> {
        match self {
            Self::Failed(failure) => Some(failure),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExecutionAttestationError {
    #[error("execution attestation signer failed")]
    SignerFailed,
    #[error("execution attestation key identifier is invalid")]
    InvalidKeyId,
    #[error("execution attestation payload is invalid")]
    InvalidPayload,
    #[error("execution attestation signature is invalid")]
    InvalidSignature,
    #[error("execution attestation key does not match the pinned identifier")]
    KeyMismatch,
    /// The receipt's evidence is missing a valid `attester_signature` from
    /// the pinned evidence attester key.
    #[error("receipt evidence attester signature is missing or invalid")]
    InvalidEvidenceSignature,
}

/// Signs gateway execution observations using an externally managed key.
///
/// `message` contains the PRÆTORE execution-attestation domain separator and
/// canonical payload. Implementations may delegate signing to a KMS/HSM.
pub trait ExecutionAttestationSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttestation {
    pub schema_version: u8,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub key_id: String,
    pub evidence_id: Uuid,
    pub request_id: Uuid,
    pub agent_id: Uuid,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    pub policy_digest: String,
    pub evidence_hash: String,
    pub action_digest: String,
    pub output_digest: Option<String>,
    pub observed_at: String,
    /// Present only on schema version 3: the closing attestation of an
    /// approved execution that was never dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_dispatched_reason: Option<NotDispatchedReason>,
    /// Present only on schema version 4: the signed classification of a
    /// `failed` execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<ExecutionFailure>,
    pub signature: String,
}

#[derive(Serialize)]
struct ExecutionAttestationPayload<'a> {
    schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    key_id: &'a str,
    evidence_id: Uuid,
    request_id: Uuid,
    agent_id: Uuid,
    authorization: AuthorizationStatus,
    execution: ExecutionStatus,
    policy_digest: &'a str,
    evidence_hash: &'a str,
    action_digest: &'a str,
    output_digest: Option<&'a str>,
    observed_at: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_dispatched_reason: Option<NotDispatchedReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<&'a ExecutionFailure>,
}

impl ExecutionAttestation {
    /// Signs an execution observation. Used by the gateway; verifiers only
    /// need [`GatewayReceipt::verify_execution_attestation`].
    ///
    /// Only available with the `signing` feature (off by default), so offline
    /// verifiers cannot mint attestations that bypass the gateway's state
    /// machine.
    #[cfg(feature = "signing")]
    pub fn create(
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        outcome: &AttestedOutcome,
        signer: &dyn ExecutionAttestationSigner,
    ) -> Result<Self, ExecutionAttestationError> {
        let key_id = signer.key_id();
        if key_id.is_empty() || key_id.len() > 256 || key_id.trim() != key_id {
            return Err(ExecutionAttestationError::InvalidKeyId);
        }
        // `AttestedOutcome` has no intermediate state, keeps an output only
        // on executed/confirmed and a failure only on failed. A reason is
        // only meaningful when closing without dispatch.
        let execution = outcome.execution();
        let output = outcome.output();
        let not_dispatched_reason = outcome.not_dispatched_reason();
        let failure = outcome.failure();
        if not_dispatched_reason.is_some_and(|reason| !reason.applies_to(authorization, execution))
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }
        let schema_version = match (not_dispatched_reason, failure) {
            (Some(_), _) => 3,
            (None, Some(_)) => 4,
            (None, None) => 2,
        };
        if !evidence.verify_integrity()
            || !evidence.is_high_assurance_shape()
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }

        let observed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let policy_digest = evidence
            .policy_digest
            .as_deref()
            .ok_or(ExecutionAttestationError::InvalidPayload)?;
        let tenant_id = authority_tenant_id(&evidence.authority)
            .ok_or(ExecutionAttestationError::InvalidPayload)?;
        let action_digest = action_digest(&evidence.action)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let output_digest = output.map(output_digest).transpose()?;
        let payload = ExecutionAttestationPayload {
            schema_version,
            tenant_id: Some(tenant_id),
            key_id,
            evidence_id: evidence.evidence_id,
            request_id: evidence.request_id,
            agent_id: *evidence.agent.id.as_uuid(),
            authorization,
            execution,
            policy_digest,
            evidence_hash: &evidence.context_hash,
            action_digest: &action_digest,
            output_digest: output_digest.as_deref(),
            observed_at: &observed_at,
            not_dispatched_reason,
            failure,
        };
        let canonical = attestation_payload_bytes(&payload)?;
        let mut message = Vec::with_capacity(EXECUTION_ATTESTATION_DOMAIN.len() + canonical.len());
        message.extend_from_slice(EXECUTION_ATTESTATION_DOMAIN);
        message.extend_from_slice(&canonical);
        let signature = signer
            .sign(&message)
            .map_err(|_| ExecutionAttestationError::SignerFailed)?;
        if signature.len() != 64 {
            return Err(ExecutionAttestationError::InvalidSignature);
        }

        Ok(Self {
            schema_version,
            tenant_id: Some(tenant_id),
            key_id: key_id.to_owned(),
            evidence_id: evidence.evidence_id,
            request_id: evidence.request_id,
            agent_id: *evidence.agent.id.as_uuid(),
            authorization,
            execution,
            policy_digest: policy_digest.to_owned(),
            evidence_hash: evidence.context_hash.clone(),
            action_digest,
            output_digest,
            observed_at,
            not_dispatched_reason,
            failure: failure.cloned(),
            signature: hex::encode(signature),
        })
    }

    fn verify(
        &self,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
        public_key: &praetore_core::VerifiedPublicKey,
        expected_key_id: &str,
    ) -> Result<(), ExecutionAttestationError> {
        if self.key_id != expected_key_id {
            return Err(ExecutionAttestationError::KeyMismatch);
        }
        self.validate_binding(evidence, authorization, execution, output)?;

        let payload = ExecutionAttestationPayload {
            schema_version: self.schema_version,
            tenant_id: self.tenant_id,
            key_id: &self.key_id,
            evidence_id: self.evidence_id,
            request_id: self.request_id,
            agent_id: self.agent_id,
            authorization: self.authorization,
            execution: self.execution,
            policy_digest: &self.policy_digest,
            evidence_hash: &self.evidence_hash,
            action_digest: &self.action_digest,
            output_digest: self.output_digest.as_deref(),
            observed_at: &self.observed_at,
            not_dispatched_reason: self.not_dispatched_reason,
            failure: self.failure.as_ref(),
        };
        let canonical = attestation_payload_bytes(&payload)?;
        let signature = hex::decode(&self.signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)?;
        public_key
            .verify_domain_message(EXECUTION_ATTESTATION_DOMAIN, &canonical, &signature)
            .map_err(|_| ExecutionAttestationError::InvalidSignature)
    }

    pub fn validate_binding(
        &self,
        evidence: &Evidence,
        authorization: AuthorizationStatus,
        execution: ExecutionStatus,
        output: Option<&Value>,
    ) -> Result<(), ExecutionAttestationError> {
        // A failure classification exists only on v4, and v4 only for
        // `failed`. A v1/v2 `failed` attestation without it predates v4 and
        // stays verifiable as history; the gateway can no longer sign one.
        if !matches!(
            (
                self.schema_version,
                self.tenant_id,
                self.not_dispatched_reason,
                &self.failure
            ),
            (1, None, None, None)
                | (2, Some(_), None, None)
                | (3, Some(_), Some(_), None)
                | (4, Some(_), None, Some(_))
        ) || self.failure.is_some() && execution != ExecutionStatus::Failed
            || self.schema_version >= 2
                && self.tenant_id != authority_tenant_id(&evidence.authority)
            || self
                .not_dispatched_reason
                .is_some_and(|reason| !reason.applies_to(authorization, execution))
            || self.evidence_id != evidence.evidence_id
            || self.request_id != evidence.request_id
            || self.agent_id != *evidence.agent.id.as_uuid()
            || self.authorization != authorization
            || authorization_for_outcome(evidence.decision.outcome) != authorization
            || self.execution != execution
            || self.policy_digest != evidence.policy_digest.as_deref().unwrap_or_default()
            || self.evidence_hash != evidence.context_hash
            || !evidence.verify_integrity()
            || authorization == AuthorizationStatus::Denied
                && execution != ExecutionStatus::NotDispatched
            || authorization == AuthorizationStatus::RequiresApproval
                && !matches!(
                    execution,
                    ExecutionStatus::NotDispatched
                        | ExecutionStatus::Executed
                        | ExecutionStatus::Confirmed
                        | ExecutionStatus::OutcomeUnknown
                        | ExecutionStatus::Failed
                )
            || matches!(
                execution,
                ExecutionStatus::Authorized
                    | ExecutionStatus::ApprovedPendingDispatch
                    | ExecutionStatus::Dispatched
            )
            || output.is_some()
                != matches!(
                    execution,
                    ExecutionStatus::Executed | ExecutionStatus::Confirmed
                )
            || self.key_id.is_empty()
            || self.key_id.len() > 256
            || self.key_id.trim() != self.key_id
            || !is_canonical_signature_hex(&self.signature)
            || OffsetDateTime::parse(&self.observed_at, &Rfc3339).is_err()
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }

        let expected_action_digest = action_digest(&evidence.action)
            .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
        let expected_output_digest = output.map(output_digest).transpose()?;
        if self.action_digest != expected_action_digest
            || self.output_digest != expected_output_digest
        {
            return Err(ExecutionAttestationError::InvalidPayload);
        }
        Ok(())
    }
}

fn authorization_for_outcome(outcome: praetore_core::DecisionOutcome) -> AuthorizationStatus {
    match outcome {
        praetore_core::DecisionOutcome::Allow => AuthorizationStatus::Allowed,
        praetore_core::DecisionOutcome::RequireApproval => AuthorizationStatus::RequiresApproval,
        praetore_core::DecisionOutcome::Deny => AuthorizationStatus::Denied,
    }
}

fn attestation_payload_bytes(
    payload: &ExecutionAttestationPayload<'_>,
) -> Result<Vec<u8>, ExecutionAttestationError> {
    let json =
        serde_json::to_string(payload).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    canonicalize_json(&json).map_err(|_| ExecutionAttestationError::InvalidPayload)
}

fn output_digest(output: &Value) -> Result<String, ExecutionAttestationError> {
    let json =
        serde_json::to_string(output).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let bytes = canonicalize_json(&json).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let mut hash = Sha256::new();
    hash.update(OUTPUT_DIGEST_DOMAIN);
    hash.update(&bytes);
    Ok(hex::encode(hash.finalize()))
}

/// A receipt keeps authorization evidence separate from the gateway's signed
/// observation of dispatch/execution. The attestation does not independently
/// prove an external effect beyond the adapter's documented contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayReceipt {
    pub evidence: Evidence,
    pub authorization: AuthorizationStatus,
    pub execution: ExecutionStatus,
    /// Adapter output of an executed or confirmed action. JSON `null` is
    /// read as `None`, so the serialized form cannot tell "no output" from
    /// an adapter that returned `null`; verification resolves this from the
    /// signed execution status (see [`Self::verify_execution_attestation`]).
    pub output: Option<Value>,
    pub execution_attestation: ExecutionAttestation,
}

impl GatewayReceipt {
    /// Verifies the execution attestation against the pinned execution key
    /// and, because the attestation binds the evidence `context_hash` (which
    /// excludes the evidence signature), also the evidence
    /// `attester_signature` against the pinned evidence attester key. There is
    /// no public way to check the attestation alone, so `Ok` always covers
    /// both signatures.
    pub fn verify_execution_attestation(
        &self,
        public_key: &praetore_core::VerifiedPublicKey,
        expected_key_id: &str,
        evidence_attester_key: &praetore_core::VerifiedPublicKey,
    ) -> Result<(), ExecutionAttestationError> {
        // `"output": null` deserializes to `None`. An executed or confirmed
        // action always has an output, so there it is the JSON value `null`,
        // whose digest the attestation signs; elsewhere it means no output.
        let output = match (&self.output, self.execution) {
            (None, ExecutionStatus::Executed | ExecutionStatus::Confirmed) => Some(&Value::Null),
            (output, _) => output.as_ref(),
        };
        self.execution_attestation.verify(
            &self.evidence,
            self.authorization,
            self.execution,
            output,
            public_key,
            expected_key_id,
        )?;
        self.verify_evidence_attester_signature(evidence_attester_key)
    }

    /// Verifies `evidence.attester_signature` against the pinned evidence
    /// attester key. The execution attestation binds the evidence's
    /// `context_hash`, which excludes this signature, so it must be checked
    /// separately.
    pub fn verify_evidence_attester_signature(
        &self,
        evidence_attester_key: &praetore_core::VerifiedPublicKey,
    ) -> Result<(), ExecutionAttestationError> {
        self.evidence
            .verify_attester_signature(evidence_attester_key)
            .map_err(|_| ExecutionAttestationError::InvalidEvidenceSignature)
    }
}

/// Parses a serialized [`GatewayReceipt`], verifies its execution
/// attestation (schema v1 to v4) against a pinned execution key, and
/// verifies the evidence `attester_signature` against a pinned evidence
/// attester key. A missing, malformed or foreign evidence signature fails
/// with [`ExecutionAttestationError::InvalidEvidenceSignature`].
///
/// Duplicate JSON keys, unknown fields and unknown `not_dispatched_reason`
/// values are rejected, as is a reason on anything but an approval closed
/// without dispatch, and a `failure` class that is unknown, malformed or on
/// anything but `failed`. This proves historical integrity only; it never
/// authorizes an action.
pub fn verify_gateway_receipt_json(
    json: &str,
    public_key: &praetore_core::VerifiedPublicKey,
    expected_key_id: &str,
    evidence_attester_key: &praetore_core::VerifiedPublicKey,
) -> Result<GatewayReceipt, ExecutionAttestationError> {
    let value = praetore_core::canonical::parse_json_rejecting_duplicates(json)
        .map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    let receipt: GatewayReceipt =
        serde_json::from_value(value).map_err(|_| ExecutionAttestationError::InvalidPayload)?;
    receipt.verify_execution_attestation(public_key, expected_key_id, evidence_attester_key)?;
    Ok(receipt)
}
