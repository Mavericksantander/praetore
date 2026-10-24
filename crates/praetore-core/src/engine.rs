use crate::{
    PraetoreError, Result,
    authority::Validity,
    authorization::AuthorizationRequest,
    canonical::parse_json_rejecting_duplicates,
    decision::Decision,
    evidence::{Evidence, EvidenceAttesterKey},
    identity::VerifiedPublicKey,
    policy::Policy,
    replay::{ReplayGuard, ReplayGuardError},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Arc};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationMode {
    Development,
    Strict,
    HighAssurance,
}

const ISSUER_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_ISSUER_KEY_V1\0ed25519\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Clone)]
pub struct HighAssuranceConfig {
    policy_digest: String,
    trusted_issuers: Vec<TrustedAuthorityIssuer>,
    evidence_attester: EvidenceAttesterKey,
    replay_guard: Option<Arc<dyn ReplayGuard>>,
}

impl std::fmt::Debug for HighAssuranceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HighAssuranceConfig")
            .field("policy_digest", &self.policy_digest)
            .field("trusted_issuers", &self.trusted_issuers)
            .field("evidence_attester", &self.evidence_attester)
            .field("replay_guard_configured", &self.replay_guard.is_some())
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
            trusted_issuers,
            evidence_attester,
            replay_guard: None,
        })
    }

    pub fn with_replay_guard(mut self, replay_guard: Arc<dyn ReplayGuard>) -> Self {
        self.replay_guard = Some(replay_guard);
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
pub struct AuthorizationEngine {
    policy: Policy,
    clock: Arc<dyn Clock>,
    mode: EvaluationMode,
    trusted_issuers: Vec<TrustedAuthorityIssuer>,
    expected_policy_digest: Option<String>,
    evidence_attester: Option<Arc<EvidenceAttesterKey>>,
    replay_guard: Option<Arc<dyn ReplayGuard>>,
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
    pub fn new(policy: Policy) -> Self {
        Self::development(policy)
    }

    pub fn development(policy: Policy) -> Self {
        Self {
            policy,
            clock: Arc::new(SystemClock),
            mode: EvaluationMode::Development,
            trusted_issuers: Vec::new(),
            expected_policy_digest: None,
            evidence_attester: None,
            replay_guard: None,
        }
    }

    /// Compatibility constructor using `Development` evaluation mode.
    pub fn with_clock(policy: Policy, clock: impl Clock + 'static) -> Self {
        Self::development_with_clock(policy, clock)
    }

    pub fn development_with_clock(policy: Policy, clock: impl Clock + 'static) -> Self {
        Self {
            policy,
            clock: Arc::new(clock),
            mode: EvaluationMode::Development,
            trusted_issuers: Vec::new(),
            expected_policy_digest: None,
            evidence_attester: None,
            replay_guard: None,
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
            clock: Arc::new(SystemClock),
            mode: EvaluationMode::Strict,
            trusted_issuers,
            expected_policy_digest: None,
            evidence_attester: None,
            replay_guard: None,
        })
    }

    pub fn strict_with_clock(
        policy: Policy,
        clock: impl Clock + 'static,
        trusted_issuers: Vec<TrustedAuthorityIssuer>,
    ) -> Result<Self> {
        let mut engine = Self::strict(policy, trusted_issuers)?;
        engine.clock = Arc::new(clock);
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
        let actual_digest = policy.digest()?;
        if actual_digest != config.policy_digest {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        if config.replay_guard.is_none() {
            return Err(PraetoreError::ReplayGuardUnavailable);
        }

        let engine = Self {
            policy,
            clock: Arc::new(clock),
            mode: EvaluationMode::HighAssurance,
            trusted_issuers: config.trusted_issuers,
            expected_policy_digest: Some(config.policy_digest),
            evidence_attester: Some(Arc::new(config.evidence_attester)),
            replay_guard: config.replay_guard,
        };
        engine.validate_production_configuration(engine.clock.now())?;
        Ok(engine)
    }

    fn validate_production_configuration(&self, now: OffsetDateTime) -> Result<()> {
        let digest = self.policy.digest()?;
        if self.expected_policy_digest.as_deref() != Some(digest.as_str())
            || self.trusted_issuers.is_empty()
            || self.evidence_attester.is_none()
            || self
                .trusted_issuers
                .iter()
                .any(|pin| !pin.is_time_bounded())
        {
            return Err(PraetoreError::PolicyIntegrityFailed);
        }
        if self.replay_guard.is_none() {
            return Err(PraetoreError::ReplayGuardUnavailable);
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

    pub fn evaluate(&self, request: AuthorizationRequest) -> Result<Evidence> {
        let now = self.clock.now();
        let replay_key = (*request.agent.id.as_uuid(), request.request_id);
        if self.mode == EvaluationMode::HighAssurance {
            self.validate_production_configuration(now)?;
        }
        let decision = self.evaluate_request(&request, now)?;
        let mut evidence = request.attest(decision)?;
        evidence.bind_policy_digest(self.policy.digest()?)?;
        if let Some(attester) = &self.evidence_attester {
            evidence.sign(attester)?;
        }
        if self.mode == EvaluationMode::HighAssurance {
            self.replay_guard
                .as_ref()
                .ok_or(PraetoreError::ReplayGuardUnavailable)?
                .claim_once(replay_key.0, replay_key.1)
                .map_err(|error| match error {
                    ReplayGuardError::AlreadyClaimed => PraetoreError::ReplayDetected,
                    ReplayGuardError::Unavailable => PraetoreError::ReplayGuardUnavailable,
                })?;
        }
        Ok(evidence)
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

        self.policy.evaluate_with_context(
            &request.agent,
            &request.authority,
            &request.action,
            &request.context,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::{Authority, Validity},
        decision::DecisionOutcome,
        identity::{AgentId, AgentIdentity, AgentKeyPair},
        policy::{Policy, PolicyRule},
        replay::ReplayGuardError,
    };
    use serde_json::json;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use uuid::Uuid;

    #[derive(Default)]
    struct TestReplayGuard {
        claims: Mutex<HashSet<(Uuid, Uuid)>>,
        unavailable: bool,
    }

    impl ReplayGuard for TestReplayGuard {
        fn claim_once(
            &self,
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
                .insert((agent_id, request_id))
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
        Policy::new(
            "test-policy",
            1,
            vec![PolicyRule::new(
                "allow-read-data",
                "read_data",
                crate::policy::PolicyEffect::Allow,
            )],
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
        let mut request =
            AuthorizationRequest::new(agent, authority, test_action().with_capability("data:read"))
                .unwrap();
        request.sign_intent(&agent_key).unwrap();

        let policy = Policy::new(
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
        let attester = EvidenceAttesterKey::generate();
        let attester_public_key = attester.public_key().unwrap();
        let replay_guard = test_replay_guard();
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            attester,
        )
        .unwrap()
        .with_replay_guard(replay_guard);
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
        let expected_policy = Policy::new("expected", 1, vec![]);
        let actual_policy = Policy::new("substituted", 1, vec![]);
        let config = HighAssuranceConfig::new(
            expected_policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            attester,
        )
        .unwrap()
        .with_replay_guard(test_replay_guard());

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
    fn production_profile_rejects_expired_issuer_pin() {
        let issuer_key = AgentKeyPair::generate();
        let policy = Policy::new("production", 1, vec![]);
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
        let policy = Policy::new("production", 1, vec![]);
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
    fn production_profile_fails_closed_when_replay_guard_is_unavailable() {
        let agent_key = AgentKeyPair::generate();
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::generate();
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read_data".into()])
                .with_validity(high_assurance_validity());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, test_action()).unwrap();
        request.sign_intent(&agent_key).unwrap();

        let policy = allow_policy();
        let config = HighAssuranceConfig::new(
            policy.digest().unwrap(),
            vec![production_test_pin(&issuer_key, high_assurance_validity())],
            EvidenceAttesterKey::generate(),
        )
        .unwrap()
        .with_replay_guard(Arc::new(TestReplayGuard {
            unavailable: true,
            ..TestReplayGuard::default()
        }));
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
