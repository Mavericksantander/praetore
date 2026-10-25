#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use praetore_core::{
    Action, AgentId, AgentKeyFingerprint, AgentKeyPair, Authority, AuthorizationRequest,
    EvidenceAttesterKey, FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig,
    Policy, PolicyEffect, PolicyRule, ReplayGuard, ReplayGuardError, TrustedAuthorityIssuer,
    authority::Validity,
    engine::{AuthorizationEngine, Clock, FixedClock},
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct FuzzReplayGuard;

impl ReplayGuard for FuzzReplayGuard {
    fn claim_once(
        &self,
        _tenant_id: Uuid,
        _agent_id: Uuid,
        _request_id: Uuid,
    ) -> std::result::Result<(), ReplayGuardError> {
        Ok(())
    }
}

struct FuzzFreshnessProvider;

impl FreshnessProvider for FuzzFreshnessProvider {
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
        agent: &AgentKeyFingerprint,
        authority_id: &praetore_core::authority::AuthorityId,
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

struct Fixture {
    engine: AuthorizationEngine,
    agent_key: AgentKeyPair,
    agent: praetore_core::AgentIdentity,
    authority: Authority,
    policy_digest: String,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let agent_key = AgentKeyPair::from_secret_bytes(&[31; 32]);
        let agent = agent_key.identity(AgentId::new());
        let issuer_key = AgentKeyPair::from_secret_bytes(&[32; 32]);
        let validity = Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        };
        let mut authority =
            Authority::new(agent.id.clone(), "fuzz-issuer", vec!["fuzz:execute".into()])
                .with_validity(validity.clone());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();

        let policy = Policy::new_v2(
            "fuzz-high-assurance",
            1,
            vec![PolicyRule::new(
                "allow-fuzz",
                "fuzz_action",
                PolicyEffect::Allow,
            )],
        );
        let issuer_pin = TrustedAuthorityIssuer::new("fuzz-issuer", issuer_key.public_key())
            .unwrap()
            .with_validity(validity)
            .unwrap();
        let policy_digest = policy.digest().unwrap();
        let config = HighAssuranceConfig::new(
            policy_digest.clone(),
            vec![issuer_pin],
            EvidenceAttesterKey::from_secret_bytes(&[33; 32]),
        )
        .unwrap()
        .with_audience("fuzz-gateway")
        .with_replay_guard(Arc::new(FuzzReplayGuard))
        .with_freshness_provider(Arc::new(FuzzFreshnessProvider));
        let engine = AuthorizationEngine::production_with_clock(
            policy,
            config,
            FixedClock::new("2026-06-01T12:00:00Z"),
        )
        .unwrap();

        Fixture {
            engine,
            agent_key,
            agent,
            authority,
            policy_digest,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(parameters) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    if !parameters.is_object() {
        return;
    }

    let mut id_bytes = [0; 16];
    let copied_id_bytes = data.len().min(id_bytes.len());
    id_bytes[..copied_id_bytes].copy_from_slice(&data[..copied_id_bytes]);
    let fixture = fixture();
    let Ok(action) = Action::new("fuzz_action", None, parameters)
        .map(|action| action.with_capability("fuzz:execute"))
    else {
        return;
    };
    let Ok(mut request) =
        AuthorizationRequest::new(fixture.agent.clone(), fixture.authority.clone(), action)
    else {
        return;
    };
    request.request_id = Uuid::from_bytes(id_bytes);
    let now = FixedClock::new("2026-06-01T12:00:00Z").now();
    if request
        .sign_intent_v2(
            &fixture.agent_key,
            "fuzz-gateway",
            now,
            now + Duration::minutes(1),
            fixture.policy_digest.clone(),
        )
        .is_ok()
    {
        let _ = fixture.engine.evaluate(request);
    }
});
