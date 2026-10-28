use crate::{
    PraetoreError, Result,
    authority::Validity,
    authorization::AuthorizationRequest,
    canonical::parse_json_rejecting_duplicates,
    decision::Decision,
    evidence::{Evidence, EvidenceAttesterKey},
    freshness::{FreshnessError, FreshnessProvider},
    identity::VerifiedPublicKey,
    policy::Policy,
    replay::{
        AtomicAuthorizationCommit, AuthorizationCommitError, CompletedAuthorization, ReplayGuard,
        ReplayGuardError,
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustedClockError {
    #[error("trusted clock is unavailable")]
    Unavailable,
    #[error("trusted clock health check failed")]
    Untrusted,
}

/// A time source that checks its trust/health status on every read and fails
/// closed when it cannot provide a trustworthy UTC instant.
pub trait TrustedClock: Send + Sync {
    fn now(&self) -> std::result::Result<OffsetDateTime, TrustedClockError>;
}

#[derive(Clone)]
enum ClockSource {
    System(Arc<dyn Clock>),
    Trusted(Arc<TrustedClockSource>),
}

struct TrustedClockSource {
    clock: Arc<dyn TrustedClock>,
    state: Mutex<TrustedClockState>,
}

struct TrustedClockState {
    last_returned: Option<OffsetDateTime>,
    failed: bool,
}

impl TrustedClockSource {
    fn new(clock: Arc<dyn TrustedClock>) -> Self {
        Self {
            clock,
            state: Mutex::new(TrustedClockState {
                last_returned: None,
                failed: false,
            }),
        }
    }

    fn now(&self) -> Result<OffsetDateTime> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PraetoreError::TrustedClockUnavailable)?;
        if state.failed {
            return Err(PraetoreError::TrustedClockUnavailable);
        }
        let now = self
            .clock
            .now()
            .map_err(|_| PraetoreError::TrustedClockUnavailable)?;
        if state.last_returned.is_some_and(|last| now < last) {
            state.failed = true;
            return Err(PraetoreError::TrustedClockUnavailable);
        }
        state.last_returned = Some(now);
        Ok(now)
    }
}

impl ClockSource {
    fn now(&self) -> Result<OffsetDateTime> {
        match self {
            Self::System(clock) => Ok(clock.now()),
            Self::Trusted(clock) => clock.now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationMode {
    Development,
    Strict,
    HighAssurance,
}

#[derive(Debug, Error)]
pub enum AtomicEvaluationError {
    #[error("authorization evaluation failed: {0}")]
    Evaluation(#[from] PraetoreError),
    #[error("atomic authorization commit failed: {0}")]
    Commit(#[from] AuthorizationCommitError),
}

const ISSUER_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_ISSUER_KEY_V1\0ed25519\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerPinDocument {
    schema_version: u8,
    issuer: String,
    key_id: String,
    algorithm: String,
    public_key: String,
    validity: Validity,
}

#[derive(Debug, Clone)]
pub struct TrustedAuthorityIssuer {
    issuer: String,
    key_id: String,
    public_key: VerifiedPublicKey,
    validity: Validity,
}

impl TrustedAuthorityIssuer {
    pub fn new(issuer: impl Into<String>, public_key: VerifiedPublicKey) -> Result<Self> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() || issuer != issuer.trim() || issuer.len() > 1024 {
            return Err(PraetoreError::InvalidRequest(
                "trusted authority issuer must be a non-empty canonical identifier".into(),
            ));
        }

        let key_id = issuer_key_id(&public_key);
        Ok(Self {
            issuer,
            key_id,
            public_key,
            validity: Validity::unbounded(),
        })
    }

    pub fn with_validity(mut self, validity: Validity) -> Result<Self> {
        validity
            .validate()
            .map_err(|_| PraetoreError::InvalidRequest("issuer pin validity is invalid".into()))?;
        self.validity = validity;
        Ok(self)
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn public_key(&self) -> &VerifiedPublicKey {
        &self.public_key
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn export_pin_json(&self) -> Result<String> {
        serde_json::to_string(&IssuerPinDocument {
            schema_version: 1,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            algorithm: "ed25519".into(),
            public_key: hex::encode(self.public_key.as_bytes()),
            validity: self.validity.clone(),
        })
        .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))
    }

    pub fn from_pin_json(json: &str) -> Result<Self> {
        if json.len() > 8192 {
            return Err(PraetoreError::TrustStoreFailure);
        }
        let value =
            parse_json_rejecting_duplicates(json).map_err(|_| PraetoreError::TrustStoreFailure)?;
        let document: IssuerPinDocument =
            serde_json::from_value(value).map_err(|_| PraetoreError::TrustStoreFailure)?;
        if document.schema_version != 1 || document.algorithm != "ed25519" {
            return Err(PraetoreError::TrustStoreFailure);
        }
        let key_bytes =
            hex::decode(&document.public_key).map_err(|_| PraetoreError::TrustStoreFailure)?;
        let public_key = VerifiedPublicKey::from_bytes(&key_bytes)
            .map_err(|_| PraetoreError::TrustStoreFailure)?;
        let pin = Self::new(document.issuer, public_key)
            .and_then(|pin| pin.with_validity(document.validity))
            .map_err(|_| PraetoreError::TrustStoreFailure)?;
        if pin.key_id != document.key_id {
            return Err(PraetoreError::TrustStoreFailure);
        }
        Ok(pin)
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> Result<bool> {
        self.validity.is_active_at(now)
    }

    pub fn verify_authority_at(
        &self,
        authority: &crate::authority::Authority,
        now: OffsetDateTime,
    ) -> Result<()> {
        if authority.issuer != self.issuer
            || authority.issuer_key_id.as_deref() != Some(self.key_id.as_str())
        {
            return Err(PraetoreError::TrustStoreFailure);
        }
        if !self.is_active_at(now)? {
            return Err(PraetoreError::TrustStoreFailure);
        }
        if authority.subject_key_hash.is_none() {
            return Err(PraetoreError::AuthorityVerificationFailed);
        }
        if !authority.validity.is_active_at(now)? {
            return Err(PraetoreError::AuthorityExpired);
        }
        authority.verify_signature(&self.public_key)
    }

    fn is_time_bounded(&self) -> bool {
        self.validity.not_after.is_some()
    }
}

fn issuer_key_id(public_key: &VerifiedPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ISSUER_KEY_ID_DOMAIN);
    hasher.update(public_key.as_bytes());
    hex::encode(hasher.finalize())
}

fn format_timestamp(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| PraetoreError::InvalidRequest("invalid evaluation timestamp".into()))
}

#[derive(Clone)]
pub struct HighAssuranceConfig {
    policy_digest: String,
    audience: Option<String>,
    max_intent_lifetime: Duration,
    max_authority_lifetime: Duration,
    max_freshness_lease: Duration,
    trusted_issuers: Vec<TrustedAuthorityIssuer>,
    tenant_issuer_bindings: Option<HashMap<Uuid, Vec<String>>>,
    evidence_attester: EvidenceAttesterKey,
    replay_guard: Option<Arc<dyn ReplayGuard>>,
    freshness_provider: Option<Arc<dyn FreshnessProvider>>,
}

impl std::fmt::Debug for HighAssuranceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HighAssuranceConfig")
            .field("policy_digest", &self.policy_digest)
            .field("audience", &self.audience)
            .field("max_intent_lifetime", &self.max_intent_lifetime)
            .field("max_authority_lifetime", &self.max_authority_lifetime)
            .field("max_freshness_lease", &self.max_freshness_lease)
            .field("trusted_issuers", &self.trusted_issuers)
            .field(
                "tenant_issuer_bindings_configured",
                &self.tenant_issuer_bindings.is_some(),
            )
            .field("evidence_attester", &self.evidence_attester)
            .field("replay_guard_configured", &self.replay_guard.is_some())
            .field(
                "freshness_provider_configured",
                &self.freshness_provider.is_some(),
            )
            .finish()
    }
}

impl HighAssuranceConfig {
    pub fn new(
        policy_digest: impl Into<String>,
        trusted_issuers: Vec<TrustedAuthorityIssuer>,
        evidence_attester: EvidenceAttesterKey,
    ) -> Result<Self> {
        let policy_digest = policy_digest.into();
        let policy_pin_bytes = hex::decode(&policy_digest).map_err(|_| {
            PraetoreError::InvalidRequest("policy pin must be a 32-byte SHA-256 hex value".into())
        })?;
        if policy_digest.len() != 64 || hex::encode(policy_pin_bytes) != policy_digest {
            return Err(PraetoreError::InvalidRequest(
                "policy pin must be a 32-byte SHA-256 hex value".into(),
            ));
        }

        if trusted_issuers.is_empty() || trusted_issuers.iter().any(|pin| !pin.is_time_bounded()) {
            return Err(PraetoreError::TrustStoreFailure);
        }

        let mut key_ids = HashSet::new();
        for pin in &trusted_issuers {
            if !key_ids.insert(&pin.key_id) {
                return Err(PraetoreError::InvalidRequest(
                    "duplicate key id in trust pins".into(),
                ));
            }
        }

        Ok(Self {
            policy_digest,
            audience: None,
            max_intent_lifetime: Duration::minutes(5),
            max_authority_lifetime: Duration::days(365),
            max_freshness_lease: Duration::minutes(1),
            trusted_issuers,
            tenant_issuer_bindings: None,
            evidence_attester,
            replay_guard: None,
            freshness_provider: None,
        })
    }

    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn with_max_intent_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_intent_lifetime = lifetime;
        self
    }

    pub fn with_max_authority_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_authority_lifetime = lifetime;
        self
    }

    pub fn with_max_freshness_lease(mut self, lifetime: Duration) -> Self {
        self.max_freshness_lease = lifetime;
        self
    }

    /// Restricts each tenant to its own issuer signing keys. Each issuer key
    /// may be assigned to only one tenant; multiple keys per tenant support
    /// planned key rotation.
    pub fn with_tenant_issuer_bindings(mut self, bindings: HashMap<Uuid, Vec<String>>) -> Self {
        self.tenant_issuer_bindings = Some(bindings);
        self
    }

    pub fn with_replay_guard(mut self, replay_guard: Arc<dyn ReplayGuard>) -> Self {
        self.replay_guard = Some(replay_guard);
        self
    }

    pub fn with_freshness_provider(
        mut self,
        freshness_provider: Arc<dyn FreshnessProvider>,
    ) -> Self {
        self.freshness_provider = Some(freshness_provider);
        self
    }
}

#[derive(Debug, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug, Clone)]
pub struct FixedClock {
    instant: OffsetDateTime,
}

impl FixedClock {
    pub fn new(timestamp: &str) -> Self {
        Self::try_new(timestamp).expect("FixedClock::new requires a valid RFC 3339 timestamp")
    }

    pub fn try_new(timestamp: &str) -> Result<Self> {
        let instant = OffsetDateTime::parse(timestamp, &Rfc3339)
            .map_err(|_| PraetoreError::InvalidRequest("invalid fixed clock timestamp".into()))?;
        Ok(Self { instant })
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.instant
    }
}

#[derive(Clone)]
/// Coordinates request validation, authority checks, policy evaluation, and
/// evidence creation.
///
/// Use `strict` for signed authority and request verification, or
/// `production` with [`HighAssuranceConfig`] for the strongest profile this
/// library provides. Development mode permits unsigned authorities and is not
/// a production security boundary.
///
/// ```
/// use praetore_core::{engine::{AuthorizationEngine, EvaluationMode}, Policy};
///
/// let engine = AuthorizationEngine::development(Policy::new("local", 1, vec![]));
/// assert_eq!(engine.mode(), EvaluationMode::Development);
/// ```
///
/// The complete signed-request examples are runnable with
/// `cargo run -p praetore-core --example quickstart`.
pub struct AuthorizationEngine {
    policy: Policy,
    clock: ClockSource,
    mode: EvaluationMode,
    trusted_issuers: Vec<TrustedAuthorityIssuer>,
    tenant_issuer_bindings: Option<HashMap<Uuid, Vec<String>>>,
    expected_policy_digest: Option<String>,
    audience: Option<String>,
    max_intent_lifetime: Duration,
    max_authority_lifetime: Duration,
    max_freshness_lease: Duration,
    evidence_attester: Option<Arc<EvidenceAttesterKey>>,
    replay_guard: Option<Arc<dyn ReplayGuard>>,
    freshness_provider: Option<Arc<dyn FreshnessProvider>>,
}

impl std::fmt::Debug for AuthorizationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationEngine")
            .field("policy", &self.policy)
            .finish()
    }
}

// Be Bold.
// The Mighty Forces Will Come to Your Aid.

impl AuthorizationEngine {
    /// Compatibility constructor using `Development` evaluation mode.
    #[cfg_attr(
        not(test),
        deprecated(
            note = "Development mode allows unsigned authorities; use AuthorizationEngine::production with HighAssuranceConfig for production"
        )
    )]
    pub fn new(policy: Policy) -> Self {
        Self::development(policy)
    }

    pub fn development(policy: Policy) -> Self {
        Self {
            policy,
            clock: ClockSource::System(Arc::new(SystemClock)),
            mode: EvaluationMode::Development,
            trusted_issuers: Vec::new(),
            tenant_issuer_bindings: None,
            expected_policy_digest: None,
            audience: None,
            max_intent_lifetime: Duration::ZERO,
            max_authority_lifetime: Duration::ZERO,
            max_freshness_lease: Duration::ZERO,
            evidence_attester: None,
            replay_guard: None,
            freshness_provider: None,
        }
    }

    /// Compatibility constructor using `Development` evaluation mode.
    #[cfg_attr(
        not(test),
        deprecated(
            note = "Development mode allows unsigned authorities; use AuthorizationEngine::production_with_clock with HighAssuranceConfig for production"
        )
    )]
    pub fn with_clock(policy: Policy, clock: impl Clock + 'static) -> Self {
        Self::development_with_clock(policy, clock)
    }

    pub fn development_with_clock(policy: Policy, clock: impl Clock + 'static) -> Self {
        Self {
            policy,
            clock: ClockSource::System(Arc::new(clock)),
            mode: EvaluationMode::Development,
            trusted_issuers: Vec::new(),
            tenant_issuer_bindings: None,
            expected_policy_digest: None,
            audience: None,
            max_intent_lifetime: Duration::ZERO,
            max_authority_lifetime: Duration::ZERO,
            max_freshness_lease: Duration::ZERO,
            evidence_attester: None,
            replay_guard: None,
            freshness_provider: None,
        }
    }

    pub fn strict(policy: Policy, trusted_issuers: Vec<TrustedAuthorityIssuer>) -> Result<Self> {
        if trusted_issuers.is_empty() {
            return Err(PraetoreError::TrustStoreFailure);
        }

        let mut key_ids = HashSet::new();
        for trusted_issuer in &trusted_issuers {
            if !key_ids.insert(&trusted_issuer.key_id) {
                return Err(PraetoreError::InvalidRequest(format!(
                    "duplicate trusted issuer key id '{}'",
                    trusted_issuer.key_id
                )));
            }
        }

        Ok(Self {
            policy,
            clock: ClockSource::System(Arc::new(SystemClock)),
            mode: EvaluationMode::Strict,
            trusted_issuers,
            tenant_issuer_bindings: None,
            expected_policy_digest: None,
            audience: None,
            max_intent_lifetime: Duration::ZERO,
            max_authority_lifetime: Duration::ZERO,
            max_freshness_lease: Duration::ZERO,
            evidence_attester: None,
            replay_guard: None,
            freshness_provider: None,
        })
    }

    pub fn strict_with_clock(
        policy: Policy,
        clock: impl Clock + 'static,
        trusted_issuers: Vec<TrustedAuthorityIssuer>,
    ) -> Result<Self> {
        let mut engine = Self::strict(policy, trusted_issuers)?;
        engine.clock = ClockSource::System(Arc::new(clock));
        Ok(engine)
    }

    pub fn production(policy: Policy, config: HighAssuranceConfig) -> Result<Self> {
        Self::production_with_clock(policy, config, SystemClock)
    }

    pub fn production_with_clock(
        policy: Policy,
        config: HighAssuranceConfig,
        clock: impl Clock + 'static,
    ) -> Result<Self> {
        Self::production_with_clock_source(policy, config, ClockSource::System(Arc::new(clock)))
    }

    /// Constructs a HighAssurance engine with a trusted, health-checked time
    /// source. The source is checked during construction and on every
    /// evaluation; an unhealthy or regressing source prevents authorization.
    pub fn production_with_trusted_clock(
        policy: Policy,
        config: HighAssuranceConfig,
        clock: impl TrustedClock + 'static,
    ) -> Result<Self> {
        Self::production_with_clock_source(
            policy,
            config,
            ClockSource::Trusted(Arc::new(TrustedClockSource::new(Arc::new(clock)))),
        )
    }

    fn production_with_clock_source(
        policy: Policy,
        config: HighAssuranceConfig,
        clock: ClockSource,
    ) -> Result<Self> {
        if policy.semantics_version != 2 {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        let actual_digest = policy.digest()?;
        if actual_digest != config.policy_digest {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        if config.replay_guard.is_none() {
            return Err(PraetoreError::ReplayGuardUnavailable);
        }
        if config.freshness_provider.is_none() {
            return Err(PraetoreError::FreshnessCheckFailed(
                FreshnessError::Unavailable,
            ));
        }
        if config.audience.as_deref().is_none_or(|audience| {
            audience.trim().is_empty() || audience != audience.trim() || audience.len() > 256
        }) || config.max_intent_lifetime <= Duration::ZERO
            || config.max_authority_lifetime <= Duration::ZERO
            || config.max_freshness_lease <= Duration::ZERO
        {
            return Err(PraetoreError::InvalidRequest(
                "HighAssurance requires a canonical audience and positive lifetime limits".into(),
            ));
        }

        let engine = Self {
            policy,
            clock,
            mode: EvaluationMode::HighAssurance,
            trusted_issuers: config.trusted_issuers,
            tenant_issuer_bindings: config.tenant_issuer_bindings,
            expected_policy_digest: Some(config.policy_digest),
            audience: config.audience,
            max_intent_lifetime: config.max_intent_lifetime,
            max_authority_lifetime: config.max_authority_lifetime,
            max_freshness_lease: config.max_freshness_lease,
            evidence_attester: Some(Arc::new(config.evidence_attester)),
            replay_guard: config.replay_guard,
            freshness_provider: config.freshness_provider,
        };
        engine.validate_production_configuration(engine.clock.now()?, true)?;
        Ok(engine)
    }

    fn validate_production_configuration(
        &self,
        now: OffsetDateTime,
        require_replay_guard: bool,
    ) -> Result<()> {
        let digest = self.policy.digest()?;
        if self.expected_policy_digest.as_deref() != Some(digest.as_str())
            || self.policy.semantics_version != 2
            || self.trusted_issuers.is_empty()
            || self.evidence_attester.is_none()
            || self.freshness_provider.is_none()
            || self
                .audience
                .as_deref()
                .is_none_or(|audience| audience.trim().is_empty() || audience != audience.trim())
            || self.max_intent_lifetime <= Duration::ZERO
            || self.max_authority_lifetime <= Duration::ZERO
            || self.max_freshness_lease <= Duration::ZERO
            || self
                .trusted_issuers
                .iter()
                .any(|pin| !pin.is_time_bounded())
        {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        if require_replay_guard && self.replay_guard.is_none() {
            return Err(PraetoreError::ReplayGuardUnavailable);
        }
        if now.checked_add(self.max_freshness_lease).is_none() {
            return Err(PraetoreError::InvalidRequest(
                "maximum freshness lease exceeds the supported clock range".into(),
            ));
        }

        if let Some(bindings) = &self.tenant_issuer_bindings {
            let mut bound_key_ids = HashSet::new();
            if bindings.is_empty() {
                return Err(PraetoreError::TrustStoreFailure);
            }
            for (tenant_id, key_ids) in bindings {
                if tenant_id.is_nil() || key_ids.is_empty() {
                    return Err(PraetoreError::TrustStoreFailure);
                }
                for key_id in key_ids {
                    let valid_key_id = key_id.len() == 64
                        && hex::decode(key_id).is_ok_and(|bytes| hex::encode(bytes) == *key_id);
                    if !valid_key_id
                        || !self.trusted_issuers.iter().any(|pin| pin.key_id == *key_id)
                        || !bound_key_ids.insert(key_id)
                    {
                        return Err(PraetoreError::TrustStoreFailure);
                    }
                }
            }
            if bound_key_ids.len() != self.trusted_issuers.len() {
                return Err(PraetoreError::TrustStoreFailure);
            }
        }

        let mut has_active_issuer = false;
        for pin in &self.trusted_issuers {
            if pin.is_active_at(now)? {
                has_active_issuer = true;
                break;
            }
        }
        if !has_active_issuer {
            return Err(PraetoreError::TrustStoreFailure);
        }
        Ok(())
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn mode(&self) -> EvaluationMode {
        self.mode
    }

    /// Checks the signed authorization's time bounds using the configured
    /// clock. This is useful for decisions that do not dispatch an action but
    /// still must not be consumed after their challenge has expired.
    pub fn validate_evidence_time_bounds(&self, evidence: &Evidence) -> Result<()> {
        if self.mode != EvaluationMode::HighAssurance
            || evidence.evidence_schema_version != 2
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
            || !evidence.verify_integrity()
        {
            return Err(PraetoreError::EvidenceError(
                "evidence is not valid HighAssurance evidence".into(),
            ));
        }
        let attester = self
            .evidence_attester
            .as_ref()
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        evidence.verify_attester_signature(&attester.public_key()?)?;
        evidence.verify_agent_intent()?;

        let intent = evidence
            .intent_v2
            .as_ref()
            .ok_or(PraetoreError::IntentInvalid)?;
        let issued_at = OffsetDateTime::parse(&intent.issued_at, &Rfc3339)
            .map_err(|_| PraetoreError::IntentInvalid)?;
        let expires_at = OffsetDateTime::parse(&intent.expires_at, &Rfc3339)
            .map_err(|_| PraetoreError::IntentInvalid)?;
        let decided_at = evidence
            .decided_at
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        let freshness_valid_until = evidence
            .freshness_valid_until
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        let now = self.clock.now()?;

        if now < issued_at || now < decided_at {
            return Err(PraetoreError::TrustedClockUnavailable);
        }
        if expires_at <= now {
            return Err(PraetoreError::IntentInvalid);
        }
        if freshness_valid_until <= now {
            return Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired));
        }
        Ok(())
    }

    /// Revalidates an attested HighAssurance authorization immediately before
    /// a gateway dispatches its bound action.
    pub fn validate_evidence_for_dispatch(&self, evidence: &Evidence) -> Result<()> {
        if self.mode != EvaluationMode::HighAssurance
            || evidence.evidence_schema_version != 2
            || evidence.evaluation_mode.as_deref() != Some("high_assurance")
            || !matches!(
                evidence.decision.outcome,
                crate::decision::DecisionOutcome::Allow
                    | crate::decision::DecisionOutcome::RequireApproval
            )
            || !evidence.verify_integrity()
        {
            return Err(PraetoreError::EvidenceError(
                "evidence is not a valid HighAssurance allow decision".into(),
            ));
        }

        let attester = self
            .evidence_attester
            .as_ref()
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        evidence.verify_attester_signature(&attester.public_key()?)?;
        evidence.verify_agent_intent()?;

        let request = AuthorizationRequest {
            request_id: evidence.request_id,
            agent: evidence.agent.clone(),
            authority: evidence.authority.clone(),
            action: evidence.action.clone(),
            trace_id: evidence.trace_id.clone(),
            context: evidence.context.clone(),
            agent_signature: evidence.agent_signature.clone(),
            intent_v2: evidence.intent_v2.clone(),
        };
        let authority_digest = request.authority.content_digest()?;
        if evidence.authority_digest.as_deref() != Some(authority_digest.as_str())
            || evidence.policy_digest.as_deref() != self.expected_policy_digest.as_deref()
            || self.expected_policy_digest.as_deref() != Some(self.policy.digest()?.as_str())
        {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }

        let decided_at = evidence
            .decided_at
            .as_deref()
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        let decided_at = OffsetDateTime::parse(decided_at, &Rfc3339)
            .map_err(|_| PraetoreError::PolicyIntegrityFailed)?;
        let freshness_valid_until = evidence
            .freshness_valid_until
            .as_deref()
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        let freshness_valid_until = OffsetDateTime::parse(freshness_valid_until, &Rfc3339)
            .map_err(|_| PraetoreError::PolicyIntegrityFailed)?;

        let now = self.clock.now()?;
        if now < decided_at {
            return Err(PraetoreError::TrustedClockUnavailable);
        }
        self.validate_production_configuration(now, false)?;
        self.validate_high_assurance_request(&request, now)?;
        let decision = self.evaluate_request(&request, now)?;
        if decision != evidence.decision {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        if freshness_valid_until <= now {
            return Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired));
        }

        let maximum_valid_until = now.checked_add(self.max_freshness_lease).ok_or_else(|| {
            PraetoreError::InvalidRequest(
                "maximum freshness lease exceeds the supported clock range".into(),
            )
        })?;
        if freshness_valid_until > maximum_valid_until {
            return Err(PraetoreError::FreshnessCheckFailed(
                FreshnessError::LeaseTooLong,
            ));
        }

        let intent = request
            .intent_v2
            .as_ref()
            .ok_or(PraetoreError::IntentInvalid)?;
        let fresh_lease = self
            .freshness_provider
            .as_ref()
            .ok_or(PraetoreError::FreshnessCheckFailed(
                FreshnessError::Unavailable,
            ))?
            .check_authority(
                &request.agent.key_fingerprint()?,
                &request.authority.id,
                &authority_digest,
                &intent.policy_digest,
                now,
            )
            .map_err(PraetoreError::FreshnessCheckFailed)?;

        let final_now = self.clock.now()?;
        if final_now < now {
            return Err(PraetoreError::TrustedClockUnavailable);
        }
        self.validate_production_configuration(final_now, false)?;
        self.validate_high_assurance_request(&request, final_now)?;
        if fresh_lease.valid_until <= final_now || freshness_valid_until <= final_now {
            return Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired));
        }
        if fresh_lease.valid_until
            > final_now
                .checked_add(self.max_freshness_lease)
                .ok_or_else(|| {
                    PraetoreError::InvalidRequest(
                        "maximum freshness lease exceeds the supported clock range".into(),
                    )
                })?
        {
            return Err(PraetoreError::FreshnessCheckFailed(
                FreshnessError::LeaseTooLong,
            ));
        }
        let final_decision = self.evaluate_request(&request, final_now)?;
        if final_decision != evidence.decision {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        Ok(())
    }

    pub fn evaluate(&self, request: AuthorizationRequest) -> Result<Evidence> {
        self.evaluate_inner(request, None)
            .map_err(|error| match error {
                AtomicEvaluationError::Evaluation(error) => error,
                AtomicEvaluationError::Commit(AuthorizationCommitError::AlreadyCommitted)
                | AtomicEvaluationError::Commit(AuthorizationCommitError::OrphanedReplayClaim) => {
                    PraetoreError::ReplayDetected
                }
                AtomicEvaluationError::Commit(AuthorizationCommitError::ConflictingRequest) => {
                    PraetoreError::InvalidRequest(
                        "authorization identity conflicts with persisted content".into(),
                    )
                }
                AtomicEvaluationError::Commit(AuthorizationCommitError::Unavailable)
                | AtomicEvaluationError::Commit(AuthorizationCommitError::NotFound) => {
                    PraetoreError::ReplayGuardUnavailable
                }
                AtomicEvaluationError::Commit(AuthorizationCommitError::InvalidRecord) => {
                    PraetoreError::EvidenceError("persisted authorization record is invalid".into())
                }
            })
    }

    /// Evaluates a new request and atomically commits its signed HighAssurance
    /// evidence with the replay claim. Unlike [`Self::evaluate`], this path
    /// never uses the configured standalone replay guard.
    pub fn evaluate_with_atomic_commit(
        &self,
        request: AuthorizationRequest,
        commit: &dyn AtomicAuthorizationCommit,
    ) -> std::result::Result<Evidence, AtomicEvaluationError> {
        if self.mode != EvaluationMode::HighAssurance {
            return Err(PraetoreError::InvalidRequest(
                "atomic authorization commit requires HighAssurance mode".into(),
            )
            .into());
        }
        self.evaluate_inner(request, Some(commit))
    }

    fn evaluate_inner(
        &self,
        request: AuthorizationRequest,
        atomic_commit: Option<&dyn AtomicAuthorizationCommit>,
    ) -> std::result::Result<Evidence, AtomicEvaluationError> {
        let now = self.clock.now()?;
        if self.mode != EvaluationMode::HighAssurance && request.intent_v2.is_some() {
            return Err(PraetoreError::InvalidRequest(
                "v2 intents are accepted only by the HighAssurance profile".into(),
            )
            .into());
        }
        let replay_key = (*request.agent.id.as_uuid(), request.request_id);
        let replay_tenant_id = request.authority.tenant_id().unwrap_or_else(Uuid::nil);
        let (intent_v2, authority_digest) = if self.mode == EvaluationMode::HighAssurance {
            self.validate_high_assurance_request(&request, now)?
        } else {
            (None, None)
        };
        if self.mode == EvaluationMode::HighAssurance {
            self.validate_production_configuration(now, atomic_commit.is_none())?;
        }
        let decision = self.evaluate_request(&request, now)?;
        let freshness = if self.mode == EvaluationMode::HighAssurance {
            let freshness = self
                .freshness_provider
                .as_ref()
                .ok_or(PraetoreError::FreshnessCheckFailed(
                    FreshnessError::Unavailable,
                ))?
                .check_authority(
                    &request.agent.key_fingerprint()?,
                    &request.authority.id,
                    authority_digest
                        .as_deref()
                        .ok_or(PraetoreError::PolicyIntegrityFailed)?,
                    self.expected_policy_digest
                        .as_deref()
                        .ok_or(PraetoreError::PolicyIntegrityFailed)?,
                    now,
                )
                .map_err(PraetoreError::FreshnessCheckFailed)?;
            if freshness.valid_until <= now {
                return Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired).into());
            }
            let maximum_valid_until =
                now.checked_add(self.max_freshness_lease).ok_or_else(|| {
                    PraetoreError::InvalidRequest(
                        "maximum freshness lease exceeds the supported clock range".into(),
                    )
                })?;
            if freshness.valid_until > maximum_valid_until {
                return Err(
                    PraetoreError::FreshnessCheckFailed(FreshnessError::LeaseTooLong).into(),
                );
            }
            Some(freshness)
        } else {
            None
        };
        let high_assurance_request =
            (self.mode == EvaluationMode::HighAssurance).then(|| request.clone());
        let mut evidence = request.attest(decision)?;
        evidence.bind_policy_digest(self.policy.digest()?)?;
        if self.mode == EvaluationMode::HighAssurance {
            let intent = intent_v2.ok_or(PraetoreError::IntentInvalid)?;
            let lease = freshness.ok_or(PraetoreError::FreshnessCheckFailed(
                FreshnessError::Unavailable,
            ))?;
            evidence.bind_high_assurance_metadata(
                format_timestamp(now)?,
                format_timestamp(lease.valid_until)?,
                authority_digest.ok_or(PraetoreError::PolicyIntegrityFailed)?,
            )?;
            if evidence.intent_v2.as_ref() != Some(&intent) {
                return Err(PraetoreError::EvidenceError(
                    "evidence intent binding changed during evaluation".into(),
                )
                .into());
            }
        }
        if let Some(attester) = &self.evidence_attester {
            evidence.sign(attester)?;
        }
        if self.mode == EvaluationMode::HighAssurance {
            let commit_now = self.clock.now()?;
            if commit_now < now {
                return Err(PraetoreError::TrustedClockUnavailable.into());
            }
            self.validate_production_configuration(commit_now, atomic_commit.is_none())?;
            let request = high_assurance_request
                .as_ref()
                .ok_or(PraetoreError::PolicyIntegrityFailed)?;
            self.validate_high_assurance_request(request, commit_now)?;
            let current_decision = self.evaluate_request(request, commit_now)?;
            if current_decision != evidence.decision {
                return Err(PraetoreError::PolicyIntegrityFailed.into());
            }
            let lease = freshness.ok_or(PraetoreError::FreshnessCheckFailed(
                FreshnessError::Unavailable,
            ))?;
            if lease.valid_until <= commit_now {
                return Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired).into());
            }
            if let Some(commit) = atomic_commit {
                let attester = self
                    .evidence_attester
                    .as_ref()
                    .ok_or(PraetoreError::PolicyIntegrityFailed)?;
                let trusted_attester = attester.public_key()?;
                evidence.verify_attester_signature(&trusted_attester)?;
                let authorization = CompletedAuthorization::new(evidence);
                match commit.commit_authorization(&authorization, &trusted_attester) {
                    Ok(()) => {}
                    Err(AuthorizationCommitError::Unavailable) => {
                        commit.verify_committed_authorization(&authorization, &trusted_attester)?;
                    }
                    Err(error) => return Err(error.into()),
                }
                evidence = authorization.evidence().clone();
            } else {
                self.replay_guard
                    .as_ref()
                    .ok_or(PraetoreError::ReplayGuardUnavailable)?
                    .claim_once(replay_tenant_id, replay_key.0, replay_key.1)
                    .map_err(|error| match error {
                        ReplayGuardError::AlreadyClaimed => PraetoreError::ReplayDetected,
                        ReplayGuardError::Unavailable => PraetoreError::ReplayGuardUnavailable,
                    })?;
            }
        }
        Ok(evidence)
    }

    fn validate_high_assurance_request(
        &self,
        request: &AuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<(
        Option<crate::authorization::AuthorizationIntentV2>,
        Option<String>,
    )> {
        let intent = request
            .intent_v2
            .as_ref()
            .ok_or(PraetoreError::IntentInvalid)?;
        let expected_audience = self
            .audience
            .as_deref()
            .ok_or(PraetoreError::PolicyIntegrityFailed)?;
        if intent.audience != expected_audience
            || self.expected_policy_digest.as_deref() != Some(intent.policy_digest.as_str())
        {
            return Err(PraetoreError::IntentInvalid);
        }

        let issued_at = OffsetDateTime::parse(&intent.issued_at, &Rfc3339)
            .map_err(|_| PraetoreError::IntentInvalid)?;
        let expires_at = OffsetDateTime::parse(&intent.expires_at, &Rfc3339)
            .map_err(|_| PraetoreError::IntentInvalid)?;
        if issued_at > now || expires_at <= now || expires_at - issued_at > self.max_intent_lifetime
        {
            return Err(PraetoreError::IntentInvalid);
        }

        let not_before = request
            .authority
            .validity
            .not_before
            .as_deref()
            .ok_or_else(|| {
                PraetoreError::InvalidRequest(
                    "HighAssurance requires bounded authority validity".into(),
                )
            })?;
        let not_after = request
            .authority
            .validity
            .not_after
            .as_deref()
            .ok_or_else(|| {
                PraetoreError::InvalidRequest(
                    "HighAssurance requires bounded authority validity".into(),
                )
            })?;
        let authority_start = OffsetDateTime::parse(not_before, &Rfc3339)
            .map_err(|_| PraetoreError::InvalidRequest("authority validity is invalid".into()))?;
        let authority_end = OffsetDateTime::parse(not_after, &Rfc3339)
            .map_err(|_| PraetoreError::InvalidRequest("authority validity is invalid".into()))?;
        if authority_end - authority_start > self.max_authority_lifetime {
            return Err(PraetoreError::InvalidRequest(
                "authority lifetime exceeds HighAssurance maximum".into(),
            ));
        }

        Ok((
            Some(intent.clone()),
            Some(request.authority.content_digest()?),
        ))
    }

    fn evaluate_request(
        &self,
        request: &AuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<Decision> {
        request.agent.validate()?;
        request.authority.validate()?;
        request.action.validate()?;

        if request.agent.id != request.authority.subject {
            return Err(PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        if self.mode != EvaluationMode::Development {
            if let Some(bindings) = &self.tenant_issuer_bindings {
                let tenant_id = request
                    .authority
                    .tenant_id()
                    .ok_or(PraetoreError::TrustStoreFailure)?;
                let key_id = request
                    .authority
                    .issuer_key_id
                    .as_deref()
                    .ok_or(PraetoreError::TrustStoreFailure)?;
                if !bindings
                    .get(&tenant_id)
                    .is_some_and(|key_ids| key_ids.iter().any(|bound| bound == key_id))
                {
                    return Err(PraetoreError::TrustStoreFailure);
                }
            }

            if request.action.capability.is_none() {
                return Err(PraetoreError::InvalidRequest(
                    "strict evaluation requires an explicit action capability".into(),
                ));
            }
            request.agent.verified_public_key()?;
            request.authority.verify_subject_identity(&request.agent)?;

            let mut matching_issuer = false;
            let mut trusted_issuer = false;
            for pin in &self.trusted_issuers {
                if pin.issuer == request.authority.issuer {
                    if request.authority.issuer_key_id.as_deref() != Some(pin.key_id.as_str()) {
                        continue;
                    }
                    matching_issuer = true;
                    if !pin.is_active_at(now)? {
                        return Err(PraetoreError::TrustStoreFailure);
                    }
                    trusted_issuer |= request.authority.verify_signature(&pin.public_key).is_ok();
                }
            }
            if !matching_issuer {
                return Err(PraetoreError::TrustStoreFailure);
            }
            if !trusted_issuer {
                return Err(PraetoreError::AuthorityVerificationFailed);
            }

            request
                .verify_intent_signature()
                .map_err(|_| PraetoreError::IntentInvalid)?;
        } else if request.agent_signature.is_some() {
            request
                .verify_intent_signature()
                .map_err(|_| PraetoreError::IntentInvalid)?;
        }

        if !request.authority.validity.is_active_at(now)? {
            return Err(PraetoreError::AuthorityExpired);
        }

        for constraint in &request.authority.constraints {
            // The gateway consumes this issuer-signed routing claim separately.
            if constraint.key == "tenant_id" {
                continue;
            }
            let satisfied = if constraint.key == "target" {
                request.action.target.as_deref() == Some(constraint.value.as_str())
            } else {
                request
                    .action
                    .parameters
                    .get(&constraint.key)
                    .and_then(|v| v.as_str())
                    == Some(constraint.value.as_str())
            };

            if !satisfied {
                return Ok(Decision::deny(format!(
                    "authority constraint '{}' was not satisfied",
                    constraint.key
                )));
            }
        }

        let capability = request
            .action
            .capability
            .as_deref()
            .unwrap_or(&request.action.action_type);
        if !request.authority.permits(capability) {
            return Ok(Decision::deny(format!(
                "authority does not permit capability: {}",
                capability
            )));
        }

        let decision = self.policy.evaluate_with_context(
            &request.agent,
            &request.authority,
            &request.action,
            &request.context,
        )?;

        // The authority check above uses a caller-chosen capability; only a
        // rule's required_capability binds the authority to the action_type.
        if self.mode != EvaluationMode::Development
            && decision.outcome != crate::decision::DecisionOutcome::Deny
        {
            if let Some(contribution) = decision.contributions.iter().find(|contribution| {
                contribution.outcome != crate::decision::DecisionOutcome::Deny
                    && self.policy.rules.iter().any(|rule| {
                        rule.id == contribution.rule_id && rule.required_capability.is_none()
                    })
            }) {
                return Ok(Decision::deny(format!(
                    "policy rule '{}' must declare required_capability",
                    contribution.rule_id
                )));
            }
        }

        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::{Authority, Validity},
        decision::DecisionOutcome,
        freshness::{FreshnessLease, FreshnessProvider},
        identity::{AgentId, AgentIdentity, AgentKeyPair},
        policy::{Policy, PolicyRule},
        replay::ReplayGuardError,
    };
    use serde_json::json;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use uuid::Uuid;

    #[derive(Default)]
    struct TestReplayGuard {
        claims: Mutex<HashSet<(Uuid, Uuid, Uuid)>>,
        unavailable: bool,
    }

    impl ReplayGuard for TestReplayGuard {
        fn claim_once(
            &self,
            tenant_id: Uuid,
            agent_id: Uuid,
            request_id: Uuid,
        ) -> std::result::Result<(), ReplayGuardError> {
            if self.unavailable {
                return Err(ReplayGuardError::Unavailable);
            }
            if self
                .claims
                .lock()
                .expect("test replay guard lock")
                .insert((tenant_id, agent_id, request_id))
            {
                Ok(())
            } else {
                Err(ReplayGuardError::AlreadyClaimed)
            }
        }
    }

    fn test_replay_guard() -> Arc<TestReplayGuard> {
        Arc::new(TestReplayGuard::default())
    }

    struct TestFreshnessProvider {
        lease_seconds: std::result::Result<i64, FreshnessError>,
    }

    impl FreshnessProvider for TestFreshnessProvider {
        fn check(
            &self,
            _agent: &crate::identity::AgentKeyFingerprint,
            _authority_id: &crate::authority::AuthorityId,
            _policy_digest: &str,
            now: OffsetDateTime,
        ) -> std::result::Result<FreshnessLease, FreshnessError> {
            let seconds = self.lease_seconds?;
            Ok(FreshnessLease {
                valid_until: now + time::Duration::seconds(seconds),
            })
        }

        fn check_authority(
            &self,
            agent: &crate::identity::AgentKeyFingerprint,
            authority_id: &crate::authority::AuthorityId,
            authority_digest: &str,
            policy_digest: &str,
            now: OffsetDateTime,
        ) -> std::result::Result<FreshnessLease, FreshnessError> {
            if authority_digest.len() != 64 {
                return Err(FreshnessError::InvalidResponse);
            }
            self.check(agent, authority_id, policy_digest, now)
        }
    }

    fn test_freshness_provider() -> Arc<dyn FreshnessProvider> {
        Arc::new(TestFreshnessProvider {
            lease_seconds: Ok(60),
        })
    }

    struct AdvancingClock(Arc<Mutex<OffsetDateTime>>);

    impl Clock for AdvancingClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().expect("test clock lock")
        }
    }

    struct AdvancingFreshnessProvider {
        clock: Arc<Mutex<OffsetDateTime>>,
        advance_by: Duration,
        lease_duration: Duration,
    }

    impl FreshnessProvider for AdvancingFreshnessProvider {
        fn check(
            &self,
            _agent: &crate::identity::AgentKeyFingerprint,
            _authority_id: &crate::authority::AuthorityId,
            _policy_digest: &str,
            now: OffsetDateTime,
        ) -> std::result::Result<FreshnessLease, FreshnessError> {
            Ok(FreshnessLease {
                valid_until: now + self.lease_duration,
            })
        }

        fn check_authority(
            &self,
            agent: &crate::identity::AgentKeyFingerprint,
            authority_id: &crate::authority::AuthorityId,
            _authority_digest: &str,
            policy_digest: &str,
            now: OffsetDateTime,
        ) -> std::result::Result<FreshnessLease, FreshnessError> {
            let mut clock = self.clock.lock().expect("test clock lock");
            *clock += self.advance_by;
            drop(clock);
            self.check(agent, authority_id, policy_digest, now)
        }
    }

    fn add_test_freshness(config: HighAssuranceConfig) -> HighAssuranceConfig {
        config
            .with_audience("test-gateway")
            .with_freshness_provider(test_freshness_provider())
    }

    fn production_engine_with_provider(
        provider: Arc<dyn FreshnessProvider>,
    ) -> (AuthorizationEngine, AuthorizationRequest) {
        production_engine_with_tenant_binding(provider, None)
    }

    fn production_engine_with_tenant_binding(
        provider: Arc<dyn FreshnessProvider>,
        tenant_binding: Option<(Uuid, Uuid)>,
    ) -> (AuthorizationEngine, AuthorizationRequest) {
        let policy = allow_policy();
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        if let Some((request_tenant_id, _)) = tenant_binding {
            authority = authority.with_constraint("tenant_id", request_tenant_id.to_string());
        }
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let policy_digest = policy.digest().unwrap();
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + time::Duration::minutes(1),
                policy_digest.clone(),
            )
            .unwrap();
        let issuer_pin = production_test_pin(&issuer_key, high_assurance_validity());
        let config = HighAssuranceConfig::new(
            policy_digest,
            vec![issuer_pin.clone()],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(test_replay_guard())
        .with_freshness_provider(provider);
        let config = if let Some((_, configured_tenant_id)) = tenant_binding {
            config.with_tenant_issuer_bindings(HashMap::from([(
                configured_tenant_id,
                vec![issuer_pin.key_id().to_owned()],
            )]))
        } else {
            config
        };
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();
        (engine, request)
    }

    struct TestTrustedClock {
        instant: OffsetDateTime,
        healthy: AtomicBool,
    }

    impl TrustedClock for TestTrustedClock {
        fn now(&self) -> std::result::Result<OffsetDateTime, TrustedClockError> {
            if self.healthy.load(Ordering::SeqCst) {
                Ok(self.instant)
            } else {
                Err(TrustedClockError::Untrusted)
            }
        }
    }

    #[test]
    fn high_assurance_fails_closed_when_trusted_clock_becomes_unhealthy() {
        let (mut engine, request) = production_engine_with_provider(test_freshness_provider());
        let clock = Arc::new(TestTrustedClock {
            instant: FixedClock::new("2026-06-01T12:00:00Z").now(),
            healthy: AtomicBool::new(false),
        });
        engine.clock = ClockSource::Trusted(Arc::new(TrustedClockSource::new(clock.clone())));

        assert!(matches!(
            engine.evaluate(request.clone()),
            Err(PraetoreError::TrustedClockUnavailable)
        ));

        clock.healthy.store(true, Ordering::SeqCst);
        assert_eq!(
            engine.evaluate(request).unwrap().decision.outcome,
            DecisionOutcome::Allow
        );
    }

    struct MutableTrustedClock {
        instant: Mutex<OffsetDateTime>,
    }

    impl TrustedClock for MutableTrustedClock {
        fn now(&self) -> std::result::Result<OffsetDateTime, TrustedClockError> {
            Ok(*self.instant.lock().unwrap())
        }
    }

    #[test]
    fn high_assurance_latches_failure_when_trusted_clock_regresses() {
        let (mut engine, request) = production_engine_with_provider(test_freshness_provider());
        let start = FixedClock::new("2026-06-01T12:00:00Z").now();
        let clock = Arc::new(MutableTrustedClock {
            instant: Mutex::new(start),
        });
        engine.clock = ClockSource::Trusted(Arc::new(TrustedClockSource::new(clock.clone())));
        let evidence = engine.evaluate(request).unwrap();

        *clock.instant.lock().unwrap() = start + Duration::minutes(2);
        assert!(matches!(
            engine.validate_evidence_time_bounds(&evidence),
            Err(PraetoreError::IntentInvalid)
        ));

        *clock.instant.lock().unwrap() = start + Duration::seconds(30);
        assert!(matches!(
            engine.validate_evidence_time_bounds(&evidence),
            Err(PraetoreError::TrustedClockUnavailable)
        ));

        *clock.instant.lock().unwrap() = start + Duration::minutes(3);
        assert!(matches!(
            engine.validate_evidence_time_bounds(&evidence),
            Err(PraetoreError::TrustedClockUnavailable)
        ));
    }

    #[test]
    fn high_assurance_tenant_issuer_binding_rejects_cross_tenant_authority() {
        let request_tenant_id = Uuid::from_u128(100);
        let configured_tenant_id = Uuid::from_u128(200);
        let (engine, request) = production_engine_with_tenant_binding(
            test_freshness_provider(),
            Some((request_tenant_id, configured_tenant_id)),
        );

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::TrustStoreFailure)
        ));
    }

    #[test]
    fn high_assurance_denies_allow_rule_without_required_capability() {
        let policy = Policy::new_v2(
            "unbound-capability",
            1,
            vec![PolicyRule::new(
                "allow-delete-data",
                "delete_data",
                crate::policy::PolicyEffect::Allow,
            )],
        );
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let action = Action::new(
            "delete_data",
            Some("database".into()),
            json!({"table":"users"}),
        )
        .unwrap()
        .with_capability("read_data");
        let policy_digest = policy.digest().unwrap();
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + time::Duration::minutes(1),
                policy_digest.clone(),
            )
            .unwrap();
        let config = HighAssuranceConfig::new(
            policy_digest,
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(test_replay_guard())
        .with_freshness_provider(test_freshness_provider());
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();

        let decision = engine.evaluate(request).unwrap().decision;

        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert!(decision.reason.contains("required_capability"));
    }

    #[test]
    fn high_assurance_tenant_issuer_binding_accepts_configured_tenant() {
        let tenant_id = Uuid::from_u128(100);
        let (engine, request) = production_engine_with_tenant_binding(
            test_freshness_provider(),
            Some((tenant_id, tenant_id)),
        );

        assert_eq!(
            engine.evaluate(request).unwrap().decision.outcome,
            DecisionOutcome::Allow
        );
    }

    struct CountingClock {
        calls: Arc<AtomicUsize>,
        instant: OffsetDateTime,
    }

    impl Clock for CountingClock {
        fn now(&self) -> OffsetDateTime {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.instant
        }
    }

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table":"users","environment":"production"}),
        )
        .unwrap()
        .with_capability("read_data")
    }

    fn allow_policy() -> Policy {
        Policy::new_v2(
            "test-policy",
            1,
            vec![
                PolicyRule::new(
                    "allow-read-data",
                    "read_data",
                    crate::policy::PolicyEffect::Allow,
                )
                .with_capability("read_data"),
            ],
        )
    }

    #[test]
    fn engine_allows_authorized_action() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn authority_within_validity_is_accepted() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: Some("2026-01-01T00:00:00Z".into()),
                not_after: Some("2026-12-31T23:59:59Z".into()),
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(engine.evaluate(request).is_ok());
    }

    #[test]
    fn authority_target_constraint_is_enforced() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "database");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn evaluation_uses_one_clock_snapshot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let clock = CountingClock {
            calls: calls.clone(),
            instant: OffsetDateTime::from_unix_timestamp(0).unwrap(),
        };
        let engine = AuthorizationEngine::development_with_clock(allow_policy(), clock);
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        engine.evaluate(request).unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn authority_parameter_constraint_is_enforced() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("environment", "production");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn authority_string_constraint_does_not_coerce_numeric_parameters() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("record_count", "12");
        let action = Action::new("read_data", None, json!({"record_count": 12})).unwrap();
        let request = AuthorizationRequest::new(agent, authority, action).unwrap();
        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_constraint_mismatch_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("environment", "staging");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_target_constraint_mismatch_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "other-database");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_missing_parameter_constraint_denies() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("region", "santiago");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn authority_requires_all_constraints() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_constraint("target", "database")
            .with_constraint("environment", "staging");

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn engine_preserves_policy_contributions() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let policy = Policy::new(
            "test-policy",
            1,
            vec![
                PolicyRule::new(
                    "allow-read-data",
                    "read_data",
                    crate::policy::PolicyEffect::Allow,
                ),
                PolicyRule::new(
                    "deny-read-data",
                    "read_data",
                    crate::policy::PolicyEffect::Deny,
                ),
            ],
        );

        let engine = AuthorizationEngine::new(policy);
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert_eq!(evidence.decision.contributions.len(), 2);
        assert!(evidence.verify());
    }

    #[test]
    fn engine_rejects_invalid_authority() {
        let agent = test_agent();

        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        authority.issuer = String::new();

        let result = AuthorizationRequest::new(agent, authority, test_action());

        assert!(matches!(result, Err(PraetoreError::InvalidRequest(_))));
    }

    #[test]
    fn engine_denies_undeclared_capability() {
        let agent = test_agent();

        let authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["write_data".into()]);

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::new(allow_policy());
        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.verify());
    }

    #[test]
    fn explicit_action_capability_is_checked_separately_from_action_type() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let action = test_action().with_capability("write:data");
        let request = AuthorizationRequest::new(agent, authority, action).unwrap();
        let engine = AuthorizationEngine::new(allow_policy());

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.decision.reason.contains("write:data"));
    }

    #[test]
    fn request_context_is_available_to_policy_and_bound_in_evidence() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        let request = AuthorizationRequest::new(agent, authority, test_action())
            .unwrap()
            .with_context("region", json!("south"));
        let policy = Policy::new(
            "context-policy",
            1,
            vec![
                PolicyRule::new(
                    "allow-south",
                    "read_data",
                    crate::policy::PolicyEffect::Allow,
                )
                .with_context_condition(crate::policy::PolicyCondition::exact(
                    "region",
                    json!("south"),
                )),
            ],
        );
        let engine = AuthorizationEngine::new(policy);

        let mut evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert_eq!(evidence.context["region"], json!("south"));
        evidence.context.insert("region".into(), json!("north"));
        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn authority_not_yet_valid_is_rejected() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: Some("2026-07-01T00:00:00Z".into()),
                not_after: None,
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityExpired)
        ));
    }

    #[test]
    fn authority_expired_is_rejected() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
            .with_validity(Validity {
                not_before: None,
                not_after: Some("2026-05-01T00:00:00Z".into()),
            });

        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        let engine = AuthorizationEngine::with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
        );

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityExpired)
        ));
    }

    #[test]
    fn engine_rejects_tampered_identity() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        request.agent.public_key.clear();

        let engine = AuthorizationEngine::new(allow_policy());

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn engine_rejects_tampered_action() {
        let agent = test_agent();

        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        request.action.parameters = json!("invalid");

        let engine = AuthorizationEngine::new(allow_policy());

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn strict_engine_rejects_unsigned_authority() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        let issuer_key = AgentKeyPair::generate();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityVerificationFailed)
        ));
    }

    #[test]
    fn strict_engine_accepts_authority_signed_by_trusted_issuer() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request.sign_intent(&agent_key).unwrap();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify_integrity());
        assert!(evidence.verify_agent_intent().is_ok());
        assert_eq!(
            evidence.policy_digest,
            Some(engine.policy().digest().unwrap())
        );
    }

    #[test]
    fn strict_mode_denies_allow_rule_without_required_capability() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let action = Action::new(
            "delete_data",
            Some("database".into()),
            json!({"table":"users"}),
        )
        .unwrap()
        .with_capability("read_data");
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request.sign_intent(&agent_key).unwrap();
        let policy = Policy::new_v2(
            "unbound-capability",
            1,
            vec![PolicyRule::new(
                "allow-delete-data",
                "delete_data",
                crate::policy::PolicyEffect::Allow,
            )],
        );
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(policy, vec![trusted_issuer]).unwrap();

        let evidence = engine.evaluate(request).unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Deny);
        assert!(evidence.decision.reason.contains("required_capability"));
    }

    #[test]
    fn strict_mode_supports_overlapping_issuer_key_rotation() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let old_issuer = AgentKeyPair::generate();
        let new_issuer = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&new_issuer, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request.sign_intent(&agent_key).unwrap();

        let engine = AuthorizationEngine::strict(
            allow_policy(),
            vec![
                TrustedAuthorityIssuer::new("praetore-root", old_issuer.public_key()).unwrap(),
                TrustedAuthorityIssuer::new("praetore-root", new_issuer.public_key()).unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(
            engine.evaluate(request).unwrap().decision.outcome,
            DecisionOutcome::Allow
        );
    }

    #[test]
    fn strict_engine_requires_agent_signed_request_intent() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::IntentInvalid)
        ));
    }

    #[test]
    fn strict_engine_rejects_expired_signed_authority() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(Validity {
                    not_before: None,
                    not_after: Some("2026-05-01T00:00:00Z".into()),
                });
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request.sign_intent(&agent_key).unwrap();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict_with_clock(
            allow_policy(),
            FixedClock::new("2026-06-01T12:00:00Z"),
            vec![trusted_issuer],
        )
        .unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityExpired)
        ));
    }

    #[test]
    fn strict_engine_rejects_authority_from_untrusted_issuer() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let actual_issuer = AgentKeyPair::generate();
        let untrusted_issuer = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&actual_issuer, &agent).unwrap();
        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", untrusted_issuer.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::TrustStoreFailure)
        ));
    }

    #[test]
    fn trusted_issuer_verification_enforces_subject_binding_and_authority_time() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let pin = TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(Validity {
                    not_before: Some("2026-01-01T00:00:00Z".into()),
                    not_after: Some("2026-05-01T00:00:00Z".into()),
                });
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let current_time = OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).unwrap();

        assert!(matches!(
            pin.verify_authority_at(&authority, current_time),
            Err(PraetoreError::AuthorityExpired)
        ));

        authority.subject_key_hash = None;
        authority.sign(&issuer_key).unwrap();
        assert!(matches!(
            pin.verify_authority_at(&authority, current_time),
            Err(PraetoreError::AuthorityVerificationFailed)
        ));
    }

    #[test]
    fn strict_engine_binds_trusted_key_to_issuer_name() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        let trusted_issuer =
            TrustedAuthorityIssuer::new("other-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::TrustStoreFailure)
        ));
    }

    #[test]
    fn strict_engine_rejects_agent_key_mismatch_with_authority() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();

        let substituted_agent = AgentKeyPair::generate().identity(agent.id.clone());
        let mut request =
            AuthorizationRequest::new(substituted_agent.clone(), authority, test_action()).unwrap();
        request.sign_intent(&AgentKeyPair::generate()).unwrap_err();

        let trusted_issuer =
            TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![trusted_issuer]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::AuthorityVerificationFailed)
        ));
    }

    fn production_test_pin(
        issuer_key: &AgentKeyPair,
        validity: Validity,
    ) -> TrustedAuthorityIssuer {
        TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key())
            .unwrap()
            .with_validity(validity)
            .unwrap()
    }

    fn high_assurance_validity() -> Validity {
        Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        }
    }

    #[test]
    fn production_profile_binds_policy_authority_intent_and_attested_evidence() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["data:read".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let policy = Policy::new_v2(
            "production-read",
            1,
            vec![
                PolicyRule::new(
                    "allow-read",
                    "read_data",
                    crate::policy::PolicyEffect::Allow,
                )
                .with_capability("data:read"),
            ],
        );
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let mut request =
            AuthorizationRequest::new(agent, authority, test_action().with_capability("data:read"))
                .unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + Duration::minutes(1),
                policy.digest().unwrap(),
            )
            .unwrap();
        let attester = EvidenceAttesterKey::generate();
        let attester_public_key = attester.public_key().unwrap();
        let replay_guard = test_replay_guard();
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            attester,
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(replay_guard);
        let config = add_test_freshness(config);
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let evaluation_threads = (0..2)
            .map(|_| {
                let engine = engine.clone();
                let request = request.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    engine.evaluate(request)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = evaluation_threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .any(|result| matches!(result, Err(PraetoreError::ReplayDetected)))
        );
        let evidence = results.into_iter().find_map(Result::ok).unwrap();

        assert_eq!(engine.mode(), EvaluationMode::HighAssurance);
        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify_integrity());
        assert_eq!(evidence.evidence_schema_version, 2);
        assert_eq!(evidence.evaluation_mode.as_deref(), Some("high_assurance"));
        assert_eq!(
            evidence.authority_digest.as_deref(),
            Some(evidence.authority.content_digest().unwrap().as_str())
        );
        assert!(evidence.verify_agent_intent().is_ok());
        assert!(
            evidence
                .verify_attester_signature(&attester_public_key)
                .is_ok()
        );
    }

    #[test]
    fn production_profile_rejects_policy_pin_mismatch() {
        let issuer_key = AgentKeyPair::generate();
        let attester = EvidenceAttesterKey::generate();
        let expected_policy = Policy::new_v2("expected", 1, vec![]);
        let actual_policy = Policy::new_v2("substituted", 1, vec![]);
        let config = HighAssuranceConfig::new(
            expected_policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            attester,
        )
        .unwrap()
        .with_replay_guard(test_replay_guard());
        let config = add_test_freshness(config);

        assert!(matches!(
            AuthorizationEngine::production_with_clock(
                actual_policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z")
            ),
            Err(PraetoreError::PolicyIntegrityFailed)
        ));
    }

    #[test]
    fn production_profile_rejects_legacy_policy_semantics() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new("legacy-policy", 1, vec![]);
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_replay_guard(test_replay_guard());
        let config = add_test_freshness(config);

        assert!(matches!(
            AuthorizationEngine::production_with_clock(
                policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z")
            ),
            Err(PraetoreError::PolicyIntegrityFailed)
        ));
    }

    #[test]
    fn production_profile_rejects_expired_issuer_pin() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new_v2("production", 1, vec![]);
        let pin = production_test_pin(
            &issuer_key,
            Validity {
                not_before: Some("2025-01-01T00:00:00Z".into()),
                not_after: Some("2026-05-01T00:00:00Z".into()),
            },
        );
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![pin],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_replay_guard(test_replay_guard());
        let config = add_test_freshness(config);

        assert!(matches!(
            AuthorizationEngine::production_with_clock(
                policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z")
            ),
            Err(PraetoreError::TrustStoreFailure)
        ));
    }

    #[test]
    fn production_profile_requires_replay_guard() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new_v2("production", 1, vec![]);
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap();

        assert!(matches!(
            AuthorizationEngine::production_with_clock(
                policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z")
            ),
            Err(PraetoreError::ReplayGuardUnavailable)
        ));
    }

    #[test]
    fn production_profile_rejects_noncanonical_audience_and_nonpositive_lifetimes() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new_v2("production", 1, vec![]);
        let build_config = || {
            HighAssuranceConfig::new(
                policy.digest().unwrap(),
                vec![production_test_pin(&issuer_key, high_assurance_validity())],
                EvidenceAttesterKey::generate(),
            )
            .unwrap()
            .with_replay_guard(test_replay_guard())
            .with_freshness_provider(test_freshness_provider())
        };
        let invalid_configs = [
            build_config().with_audience(""),
            build_config().with_audience(" trailing"),
            build_config().with_audience("a".repeat(257)),
            build_config()
                .with_audience("valid")
                .with_max_intent_lifetime(Duration::ZERO),
            build_config()
                .with_audience("valid")
                .with_max_authority_lifetime(Duration::seconds(-1)),
            build_config()
                .with_audience("valid")
                .with_max_freshness_lease(Duration::ZERO),
            build_config()
                .with_audience("valid")
                .with_max_freshness_lease(Duration::MAX),
        ];

        for config in invalid_configs {
            assert!(matches!(
                AuthorizationEngine::production_with_clock(
                    policy.clone(),
                    config,
                    FixedClock::new("2026-06-01T12:00:00Z")
                ),
                Err(PraetoreError::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn production_profile_rejects_invalid_tenant_issuer_bindings() {
        let issuer_key = AgentKeyPair::generate();
        let second_issuer_key = AgentKeyPair::generate();
        let policy = Policy::new_v2("production", 1, vec![]);
        let issuer_pin = production_test_pin(&issuer_key, high_assurance_validity());
        let second_issuer_pin = production_test_pin(&second_issuer_key, high_assurance_validity());
        let issuer_key_id = issuer_pin.key_id().to_owned();
        let second_issuer_key_id = second_issuer_pin.key_id().to_owned();
        let base_config = || {
            HighAssuranceConfig::new(
                policy.digest().unwrap(),
                vec![issuer_pin.clone(), second_issuer_pin.clone()],
                EvidenceAttesterKey::generate(),
            )
            .unwrap()
            .with_audience("test-gateway")
            .with_replay_guard(test_replay_guard())
            .with_freshness_provider(test_freshness_provider())
        };
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let invalid_bindings = [
            HashMap::new(),
            HashMap::from([(Uuid::nil(), vec![issuer_key_id.clone()])]),
            HashMap::from([(tenant_a, Vec::new())]),
            HashMap::from([(tenant_a, vec!["A".repeat(64)])]),
            HashMap::from([(tenant_a, vec!["f".repeat(64)])]),
            HashMap::from([
                (tenant_a, vec![issuer_key_id.clone()]),
                (tenant_b, vec![issuer_key_id.clone()]),
            ]),
            HashMap::from([(tenant_a, vec![issuer_key_id.clone()])]),
        ];

        for bindings in invalid_bindings {
            let config = base_config().with_tenant_issuer_bindings(bindings);
            assert!(matches!(
                AuthorizationEngine::production_with_clock(
                    policy.clone(),
                    config,
                    FixedClock::new("2026-06-01T12:00:00Z")
                ),
                Err(PraetoreError::TrustStoreFailure)
            ));
        }

        let valid_bindings = HashMap::from([
            (tenant_a, vec![issuer_key_id]),
            (tenant_b, vec![second_issuer_key_id]),
        ]);
        let engine = AuthorizationEngine::production_with_clock(
            policy.clone(),
            base_config().with_tenant_issuer_bindings(valid_bindings),
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();
        assert_eq!(engine.mode(), EvaluationMode::HighAssurance);
    }

    #[test]
    fn production_profile_fails_closed_when_replay_guard_is_unavailable() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let policy = allow_policy();
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + Duration::minutes(1),
                policy.digest().unwrap(),
            )
            .unwrap();

        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(Arc::new(TestReplayGuard {
            unavailable: true,
            ..TestReplayGuard::default()
        }));
        let config = add_test_freshness(config);
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::ReplayGuardUnavailable)
        ));
    }

    #[test]
    fn production_freshness_provider_must_vouch_for_current_state() {
        let zero_length_provider = Arc::new(TestFreshnessProvider {
            lease_seconds: Ok(0),
        });
        let (engine, request) = production_engine_with_provider(zero_length_provider);
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired))
        ));

        for error in [
            FreshnessError::Revoked,
            FreshnessError::Unknown,
            FreshnessError::Expired,
            FreshnessError::Unavailable,
            FreshnessError::InvalidResponse,
        ] {
            let provider = Arc::new(TestFreshnessProvider {
                lease_seconds: Err(error),
            });
            let (engine, request) = production_engine_with_provider(provider);
            let result = engine.evaluate(request);
            assert!(matches!(
                result,
                Err(PraetoreError::FreshnessCheckFailed(actual)) if actual == error
            ));
            assert_eq!(result.unwrap_err().code(), error.code());
        }

        let expired_provider = Arc::new(TestFreshnessProvider {
            lease_seconds: Ok(-1),
        });
        let (engine, request) = production_engine_with_provider(expired_provider);
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired))
        ));

        let excessive_lease_provider = Arc::new(TestFreshnessProvider {
            lease_seconds: Ok(61),
        });
        let (engine, request) = production_engine_with_provider(excessive_lease_provider);
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::FreshnessCheckFailed(
                FreshnessError::LeaseTooLong
            ))
        ));
    }

    #[test]
    fn production_rechecks_freshness_before_consuming_replay_claim() {
        let policy = allow_policy();
        let policy_digest = policy.digest().unwrap();
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let clock = Arc::new(Mutex::new(now));
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + Duration::minutes(4),
                policy_digest.clone(),
            )
            .unwrap();
        let replay_guard = test_replay_guard();
        let config = HighAssuranceConfig::new(
            policy_digest,
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(replay_guard.clone())
        .with_freshness_provider(Arc::new(AdvancingFreshnessProvider {
            clock: clock.clone(),
            advance_by: Duration::seconds(31),
            lease_duration: Duration::seconds(30),
        }));
        let engine =
            AuthorizationEngine::production_with_clock(policy, config, AdvancingClock(clock))
                .unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired))
        ));
        assert!(replay_guard.claims.lock().unwrap().is_empty());
    }

    #[test]
    fn dispatch_validation_rejects_evidence_after_its_freshness_lease_expires() {
        let policy = allow_policy();
        let policy_digest = policy.digest().unwrap();
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let clock = Arc::new(Mutex::new(now));
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                now,
                now + Duration::minutes(4),
                policy_digest.clone(),
            )
            .unwrap();
        let config = HighAssuranceConfig::new(
            policy_digest,
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_audience("test-gateway")
        .with_replay_guard(test_replay_guard())
        .with_freshness_provider(Arc::new(AdvancingFreshnessProvider {
            clock: clock.clone(),
            advance_by: Duration::ZERO,
            lease_duration: Duration::seconds(30),
        }));
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            AdvancingClock(clock.clone()),
        )
        .unwrap();

        let evidence = engine.evaluate(request).unwrap();
        *clock.lock().unwrap() = now + Duration::seconds(30);

        assert!(matches!(
            engine.validate_evidence_for_dispatch(&evidence),
            Err(PraetoreError::FreshnessCheckFailed(FreshnessError::Expired))
        ));
    }

    #[test]
    fn production_profile_rejects_invalid_intent_metadata_and_unbounded_authority() {
        let (engine, mut request) = production_engine_with_provider(test_freshness_provider());
        request.intent_v2.as_mut().unwrap().audience = "other-gateway".into();
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::IntentInvalid)
        ));

        let (engine, mut request) = production_engine_with_provider(test_freshness_provider());
        request.intent_v2.as_mut().unwrap().policy_digest = "0".repeat(64);
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::IntentInvalid)
        ));

        let (engine, mut request) = production_engine_with_provider(test_freshness_provider());
        request.intent_v2.as_mut().unwrap().expires_at = "2026-06-01T12:00:00Z".into();
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::IntentInvalid)
        ));

        let (engine, mut request) = production_engine_with_provider(test_freshness_provider());
        request.authority.validity.not_after = None;
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidRequest(_))
        ));

        let (engine, mut request) = production_engine_with_provider(test_freshness_provider());
        request.authority.validity.not_before = Some("2020-01-01T00:00:00Z".into());
        request.authority.validity.not_after = Some("2030-01-01T00:00:00Z".into());
        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn production_profile_rejects_future_and_overlong_intent_windows() {
        let now = FixedClock::new("2026-06-01T12:00:00Z").now();
        let make_signed_case = |issued_at: OffsetDateTime, expires_at: OffsetDateTime| {
            let policy = allow_policy();
            let policy_digest = policy.digest().unwrap();
            let agent_key = AgentKeyPair::generate();
            let agent = agent_key.identity(AgentId::new());
            let issuer_key = AgentKeyPair::generate();
            let mut authority =
                Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                    .with_validity(high_assurance_validity());
            authority.sign_for_agent(&issuer_key, &agent).unwrap();
            let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
            request
                .sign_intent_v2(
                    &agent_key,
                    "test-gateway",
                    issued_at,
                    expires_at,
                    policy_digest.clone(),
                )
                .unwrap();
            let config = HighAssuranceConfig::new(
                policy_digest,
                vec![production_test_pin(&issuer_key, high_assurance_validity())],
                EvidenceAttesterKey::generate(),
            )
            .unwrap()
            .with_audience("test-gateway")
            .with_replay_guard(test_replay_guard())
            .with_freshness_provider(test_freshness_provider());
            let engine = AuthorizationEngine::production_with_clock(
                policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z"),
            )
            .unwrap();
            (engine, request)
        };
        let invalid_windows = [
            (now + Duration::seconds(1), now + Duration::minutes(1)),
            (now, now + Duration::minutes(6)),
            (now - Duration::minutes(2), now - Duration::minutes(1)),
            (now - Duration::minutes(1), now),
        ];

        for (issued_at, expires_at) in invalid_windows {
            let (engine, request) = make_signed_case(issued_at, expires_at);
            assert!(matches!(
                engine.evaluate(request),
                Err(PraetoreError::IntentInvalid)
            ));
        }
    }

    #[test]
    fn production_freshness_provider_receives_exact_authority_digest() {
        struct RecordingProvider(Arc<Mutex<Option<String>>>);

        impl FreshnessProvider for RecordingProvider {
            fn check(
                &self,
                _agent: &crate::identity::AgentKeyFingerprint,
                _authority_id: &crate::authority::AuthorityId,
                _policy_digest: &str,
                now: OffsetDateTime,
            ) -> std::result::Result<FreshnessLease, FreshnessError> {
                Ok(FreshnessLease {
                    valid_until: now + time::Duration::minutes(1),
                })
            }

            fn check_authority(
                &self,
                agent: &crate::identity::AgentKeyFingerprint,
                authority_id: &crate::authority::AuthorityId,
                authority_digest: &str,
                policy_digest: &str,
                now: OffsetDateTime,
            ) -> std::result::Result<FreshnessLease, FreshnessError> {
                *self.0.lock().unwrap() = Some(authority_digest.to_owned());
                self.check(agent, authority_id, policy_digest, now)
            }
        }

        let observed_digest = Arc::new(Mutex::new(None));
        let provider = Arc::new(RecordingProvider(observed_digest.clone()));
        let (engine, request) = production_engine_with_provider(provider);
        let expected_digest = request.authority.content_digest().unwrap();

        assert!(engine.evaluate(request).is_ok());
        assert_eq!(
            observed_digest.lock().unwrap().as_deref(),
            Some(expected_digest.as_str())
        );
    }

    #[test]
    fn production_profile_requires_freshness_provider() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new_v2("production", 1, vec![]);
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_replay_guard(test_replay_guard());
        assert!(matches!(
            AuthorizationEngine::production_with_clock(
                policy,
                config,
                FixedClock::new("2026-06-01T12:00:00Z")
            ),
            Err(PraetoreError::FreshnessCheckFailed(
                FreshnessError::Unavailable
            ))
        ));
    }

    #[test]
    fn issuer_pin_json_round_trips_and_rejects_tampering() {
        let issuer_key = AgentKeyPair::generate();
        let pin = production_test_pin(&issuer_key, high_assurance_validity());
        let serialized = pin.export_pin_json().unwrap();

        let restored = TrustedAuthorityIssuer::from_pin_json(&serialized).unwrap();
        assert_eq!(restored.issuer(), "praetore-root");
        assert_eq!(restored.key_id(), pin.key_id());
        assert_eq!(restored.export_pin_json().unwrap(), serialized);

        let tampered = serialized.replace("ed25519", "rsa");
        assert!(matches!(
            TrustedAuthorityIssuer::from_pin_json(&tampered),
            Err(PraetoreError::TrustStoreFailure)
        ));
        assert!(matches!(
            TrustedAuthorityIssuer::from_pin_json(r#"{"schema_version":1,"schema_version":1}"#),
            Err(PraetoreError::TrustStoreFailure)
        ));
    }

    #[test]
    fn strict_mode_rejects_implicit_action_type_capability() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut action = test_action();
        action.capability = None;
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request.sign_intent(&agent_key).unwrap();
        let pin = TrustedAuthorityIssuer::new("praetore-root", issuer_key.public_key()).unwrap();
        let engine = AuthorizationEngine::strict(allow_policy(), vec![pin]).unwrap();

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn concurrent_engine_evaluations_keep_decisions_isolated() {
        let engine = Arc::new(AuthorizationEngine::new(allow_policy()));
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        let action = test_action();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let agent = agent.clone();
                let authority = authority.clone();
                let action = action.clone();
                std::thread::spawn(move || {
                    let request = AuthorizationRequest::new(agent, authority, action).unwrap();
                    engine.evaluate(request).unwrap().decision.outcome
                })
            })
            .collect();

        for handle in handles {
            assert_eq!(handle.join().unwrap(), DecisionOutcome::Allow);
        }
    }

    #[test]
    fn engine_rejects_invalid_request_signature_even_in_development_mode() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request.sign_intent(&agent_key).unwrap();
        request.agent_signature = Some("00".repeat(64));
        let engine = AuthorizationEngine::new(allow_policy());

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::IntentInvalid)
        ));
    }

    #[test]
    fn engine_rejects_mismatched_identity_and_authority_after_construction() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()]);

        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();

        request.agent.id = AgentId::new();

        let engine = AuthorizationEngine::new(allow_policy());

        assert!(matches!(
            engine.evaluate(request),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }
}
