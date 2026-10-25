use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use praetore_core::{
    Action, AgentId, AgentIdentity, AgentKeyFingerprint, AgentKeyPair, Authority,
    AuthorizationRequest, DecisionOutcome, Evidence, EvidenceAttesterKey, FreshnessError,
    FreshnessLease, FreshnessProvider, HighAssuranceConfig, Policy, PolicyCondition, PolicyEffect,
    PolicyRule, ReplayGuard, ReplayGuardError, Result, TrustedAuthorityIssuer,
    authority::{AuthorityId, Validity},
    engine::{AuthorizationEngine, Clock, FixedClock},
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct LocalReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl Default for LocalReplayGuard {
    fn default() -> Self {
        Self(Mutex::new(HashSet::new()))
    }
}

impl ReplayGuard for LocalReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> std::result::Result<(), ReplayGuardError> {
        let mut claims = self.0.lock().map_err(|_| ReplayGuardError::Unavailable)?;
        if claims.insert((tenant_id, agent_id, request_id)) {
            Ok(())
        } else {
            Err(ReplayGuardError::AlreadyClaimed)
        }
    }
}

struct DemonstrationFreshnessProvider;

impl FreshnessProvider for DemonstrationFreshnessProvider {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> std::result::Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + Duration::minutes(1),
        })
    }

    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        authority_digest: &str,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> std::result::Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64 {
            return Err(FreshnessError::InvalidResponse);
        }
        Ok(FreshnessLease {
            valid_until: now + Duration::minutes(1),
        })
    }
}

fn make_request(
    agent_key: &AgentKeyPair,
    agent: &AgentIdentity,
    authority: &Authority,
) -> Result<AuthorizationRequest> {
    let action = Action::new(
        "read_data",
        Some("example-dataset".into()),
        serde_json::json!({"classification": "public", "region": "west"}),
    )?
    .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent.clone(), authority.clone(), action)?
        .with_context("region", serde_json::json!("west"));
    request.sign_intent(agent_key)?;
    Ok(request)
}

fn make_high_assurance_request(
    agent_key: &AgentKeyPair,
    agent: &AgentIdentity,
    authority: &Authority,
    policy_digest: &str,
    now: OffsetDateTime,
) -> Result<AuthorizationRequest> {
    let action = Action::new(
        "read_data",
        Some("example-dataset".into()),
        serde_json::json!({"classification": "public", "region": "west"}),
    )?
    .with_capability("data:read");
    let mut request = AuthorizationRequest::new(agent.clone(), authority.clone(), action)?
        .with_context("region", serde_json::json!("west"));
    request.sign_intent_v2(
        agent_key,
        "quickstart-gateway",
        now,
        now + Duration::minutes(1),
        policy_digest,
    )?;
    Ok(request)
}

fn verify_common_evidence(
    evidence: &Evidence,
    issuer_pin: &TrustedAuthorityIssuer,
    expected_policy_digest: &str,
    now: OffsetDateTime,
) -> Result<()> {
    assert!(evidence.verify_integrity());
    evidence.verify_agent_intent()?;
    issuer_pin.verify_authority_at(&evidence.authority, now)?;
    evidence
        .authority
        .verify_subject_identity(&evidence.agent)?;
    assert_eq!(
        evidence.policy_digest.as_deref(),
        Some(expected_policy_digest)
    );
    Ok(())
}

fn main() -> Result<()> {
    let now = FixedClock::new("2026-06-01T12:00:00Z");
    let evaluation_time = now.now();
    let validity = Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2027-01-01T00:00:00Z".into()),
    };

    let agent_key = AgentKeyPair::generate();
    let agent = agent_key.identity(AgentId::new());
    let issuer_key = AgentKeyPair::generate();

    let mut authority = Authority::new(
        agent.id.clone(),
        "quickstart-issuer",
        vec!["data:read".into()],
    )
    .with_validity(validity.clone());
    authority.sign_for_agent(&issuer_key, &agent)?;

    let policy = Policy::new_v2(
        "quickstart-policy",
        1,
        vec![
            PolicyRule::new("deny-restricted", "read_data", PolicyEffect::Deny)
                .with_parameter_condition(PolicyCondition::exact(
                    "classification",
                    serde_json::json!("restricted"),
                )),
            PolicyRule::new("allow-public-west", "read_data", PolicyEffect::Allow)
                .with_capability("data:read")
                .with_parameter_condition(PolicyCondition::exact(
                    "classification",
                    serde_json::json!("public"),
                ))
                .with_context_condition(PolicyCondition::one_of(
                    "region",
                    vec![serde_json::json!("west"), serde_json::json!("central")],
                )),
        ],
    );
    let issuer_pin = TrustedAuthorityIssuer::new("quickstart-issuer", issuer_key.public_key())?
        .with_validity(validity)?;
    let policy_digest = policy.digest()?;

    let strict_engine =
        AuthorizationEngine::strict_with_clock(policy.clone(), now, vec![issuer_pin.clone()])?;
    let strict_evidence = strict_engine.evaluate(make_request(&agent_key, &agent, &authority)?)?;
    assert_eq!(strict_evidence.decision.outcome, DecisionOutcome::Allow);
    verify_common_evidence(
        &strict_evidence,
        &issuer_pin,
        &policy_digest,
        evaluation_time,
    )?;
    println!("Strict: ALLOW; request intent, issuer authority, and evidence integrity verified.");

    let attester = EvidenceAttesterKey::generate();
    let attester_public_key = attester.public_key()?;
    let high_assurance_config =
        HighAssuranceConfig::new(policy_digest.clone(), vec![issuer_pin.clone()], attester)?
            .with_audience("quickstart-gateway")
            .with_replay_guard(Arc::new(LocalReplayGuard::default()))
            .with_freshness_provider(Arc::new(DemonstrationFreshnessProvider));
    let high_assurance_engine = AuthorizationEngine::production_with_clock(
        policy,
        high_assurance_config,
        FixedClock::new("2026-06-01T12:00:00Z"),
    )?;
    let high_assurance_evidence = high_assurance_engine.evaluate(make_high_assurance_request(
        &agent_key,
        &agent,
        &authority,
        &policy_digest,
        evaluation_time,
    )?)?;
    assert_eq!(
        high_assurance_evidence.decision.outcome,
        DecisionOutcome::Allow
    );
    verify_common_evidence(
        &high_assurance_evidence,
        &issuer_pin,
        &policy_digest,
        evaluation_time,
    )?;
    high_assurance_evidence.verify_attester_signature(&attester_public_key)?;
    println!(
        "HighAssurance: ALLOW; intent, issuer authority, attester signature, and evidence integrity verified."
    );
    Ok(())
}
