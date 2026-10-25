use praetore_core::{
    Action, AgentId, AgentKeyPair, Authority, AuthorizationRequest, EvidenceAttesterKey, Policy,
    PolicyEffect, PolicyRule, Result, TrustedAuthorityIssuer,
    authority::Validity,
    engine::{AuthorizationEngine, Clock, FixedClock},
    freshness::{FreshnessError, FreshnessLease, FreshnessProvider},
    identity::AgentKeyFingerprint,
    replay::{ReplayGuard, ReplayGuardError},
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Default)]
struct ExampleReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl ReplayGuard for ExampleReplayGuard {
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

struct ExampleFreshnessProvider;

impl FreshnessProvider for ExampleFreshnessProvider {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &praetore_core::authority::AuthorityId,
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
        _authority_id: &praetore_core::authority::AuthorityId,
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

fn main() -> Result<()> {
    let validity = Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2027-01-01T00:00:00Z".into()),
    };
    let agent_key = AgentKeyPair::generate();
    let agent = agent_key.identity(AgentId::new());
    let issuer_key = AgentKeyPair::generate();
    let attester_key = EvidenceAttesterKey::generate();
    let attester_public_key = attester_key.public_key()?;
    let clock = FixedClock::try_new("2026-06-01T12:00:00Z")?;
    let now = clock.now();

    let mut authority =
        Authority::new(agent.id.clone(), "example-issuer", vec!["data:read".into()])
            .with_validity(validity.clone());
    authority.sign_for_agent(&issuer_key, &agent)?;

    let mut request = AuthorizationRequest::new(
        agent,
        authority,
        Action::new(
            "read_data",
            Some("example-dataset".into()),
            serde_json::json!({}),
        )?
        .with_capability("data:read"),
    )?;
    let policy = Policy::new_v2(
        "example-policy",
        1,
        vec![
            PolicyRule::new("allow-example-read", "read_data", PolicyEffect::Allow)
                .with_capability("data:read"),
        ],
    );
    request.sign_intent_v2(
        &agent_key,
        "example-gateway",
        now,
        now + Duration::minutes(1),
        policy.digest()?,
    )?;
    let issuer_pin = TrustedAuthorityIssuer::new("example-issuer", issuer_key.public_key())?
        .with_validity(validity)?;
    let config =
        praetore_core::HighAssuranceConfig::new(policy.digest()?, vec![issuer_pin], attester_key)?
            .with_audience("example-gateway")
            .with_replay_guard(Arc::new(ExampleReplayGuard::default()))
            .with_freshness_provider(Arc::new(ExampleFreshnessProvider));
    let engine = AuthorizationEngine::production_with_clock(policy, config, clock)?;

    let evidence = engine.evaluate(request)?;
    evidence.verify_agent_intent()?;
    evidence.verify_attester_signature(&attester_public_key)?;
    println!("{}", evidence.to_json()?);
    Ok(())
}
