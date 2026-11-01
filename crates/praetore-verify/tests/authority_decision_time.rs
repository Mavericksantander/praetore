//! `praetore-verify evidence --issuer-pins` checks the embedded authority at
//! the receipt's signed decision time (`decided_at`), not at the verifier's
//! clock. These receipts are built with a fixed engine clock in January 2026,
//! with an authority that expired on 2026-02-01, so on any later day a check
//! against "now" would fail with AUTHORITY_EXPIRED.

use praetore_core::{
    Evidence,
    action::Action,
    authority::{Authority, Validity},
    authorization::AuthorizationRequest,
    canonical::canonicalize_json,
    engine::{AuthorizationEngine, FixedClock, HighAssuranceConfig, TrustedAuthorityIssuer},
    evidence::EvidenceAttesterKey,
    freshness::{FreshnessError, FreshnessLease, FreshnessProvider},
    identity::{AgentId, AgentKeyPair},
    policy::{Policy, PolicyEffect, PolicyRule},
    replay::{ReplayGuard, ReplayGuardError},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const PIN_NOT_BEFORE: &str = "2025-01-01T00:00:00Z";
const PIN_NOT_AFTER: &str = "2030-01-01T00:00:00Z";
const AUTHORITY_NOT_BEFORE: &str = "2026-01-10T00:00:00Z";
const AUTHORITY_NOT_AFTER: &str = "2026-02-01T00:00:00Z";
const INTENT_ISSUED_AT: &str = "2026-01-05T00:00:00Z";
const INTENT_EXPIRES_AT: &str = "2026-03-01T00:00:00Z";
const DECIDED_AT: &str = "2026-01-15T12:00:00Z";

#[derive(Default)]
struct TestReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl ReplayGuard for TestReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), ReplayGuardError> {
        if self
            .0
            .lock()
            .unwrap()
            .insert((tenant_id, agent_id, request_id))
        {
            Ok(())
        } else {
            Err(ReplayGuardError::AlreadyClaimed)
        }
    }
}

struct TestFreshnessProvider;

impl FreshnessProvider for TestFreshnessProvider {
    fn check(
        &self,
        _agent: &praetore_core::AgentKeyFingerprint,
        _authority_id: &praetore_core::AuthorityId,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + Duration::seconds(30),
        })
    }

    fn check_authority(
        &self,
        agent: &praetore_core::AgentKeyFingerprint,
        authority_id: &praetore_core::AuthorityId,
        _authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        self.check(agent, authority_id, policy_digest, now)
    }
}

struct Fixture {
    directory: PathBuf,
    attester: EvidenceAttesterKey,
    evidence: Evidence,
}

impl Fixture {
    /// An honest HighAssurance receipt decided at `DECIDED_AT` by an engine
    /// whose clock is fixed at that instant.
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "praetore-verify-decision-time-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();

        let agent_key = AgentKeyPair::from_secret_bytes(&[21; 32]);
        let issuer_key = AgentKeyPair::from_secret_bytes(&[22; 32]);
        let attester = EvidenceAttesterKey::from_secret_bytes(&[23; 32]);
        let agent = agent_key.identity(AgentId::new());
        let mut authority =
            Authority::new(agent.id.clone(), "test-issuer", vec!["data:read".into()])
                .with_validity(Validity {
                    not_before: Some(AUTHORITY_NOT_BEFORE.into()),
                    not_after: Some(AUTHORITY_NOT_AFTER.into()),
                });
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        let action = Action::new("read_data", Some("db".into()), json!({"table": "users"}))
            .unwrap()
            .with_capability("data:read");
        let policy = Policy::new_v2(
            "decision-time-test",
            1,
            vec![
                PolicyRule::new("allow-read", "read_data", PolicyEffect::Allow)
                    .with_capability("data:read"),
            ],
        );
        let issuer_pin = TrustedAuthorityIssuer::new("test-issuer", issuer_key.public_key())
            .unwrap()
            .with_validity(Validity {
                not_before: Some(PIN_NOT_BEFORE.into()),
                not_after: Some(PIN_NOT_AFTER.into()),
            })
            .unwrap();
        let policy_digest = policy.digest().unwrap();
        let mut request = AuthorizationRequest::new(agent, authority, action).unwrap();
        request
            .sign_intent_v2(
                &agent_key,
                "test-gateway",
                parse(INTENT_ISSUED_AT),
                parse(INTENT_EXPIRES_AT),
                policy_digest.clone(),
            )
            .unwrap();
        let config =
            HighAssuranceConfig::new(policy_digest, vec![issuer_pin.clone()], attester.clone())
                .unwrap()
                .with_audience("test-gateway")
                .with_max_intent_lifetime(Duration::days(60))
                .with_replay_guard(Arc::new(TestReplayGuard::default()))
                .with_freshness_provider(Arc::new(TestFreshnessProvider));
        let engine =
            AuthorizationEngine::production_with_clock(policy, config, FixedClock::new(DECIDED_AT))
                .unwrap();
        let evidence = engine.evaluate(request).unwrap();
        assert!(evidence.is_high_assurance_shape());
        assert_eq!(evidence.decided_at.as_deref(), Some(DECIDED_AT));

        fs::write(
            directory.join("attester-pin.hex"),
            hex::encode(attester.public_key().unwrap().as_bytes()),
        )
        .unwrap();
        fs::write(
            directory.join("issuer-pins.jsonl"),
            format!("{}\n", issuer_pin.export_pin_json().unwrap()),
        )
        .unwrap();
        Self {
            directory,
            attester,
            evidence,
        }
    }

    fn verify(&self, evidence_json: &str) -> Value {
        let path = self.directory.join(format!("{}.json", Uuid::new_v4()));
        fs::write(&path, evidence_json).unwrap();
        let output = run(&[
            "evidence".into(),
            "--evidence".into(),
            path.to_string_lossy().into_owned(),
            "--attester-pin".into(),
            self.directory
                .join("attester-pin.hex")
                .to_string_lossy()
                .into_owned(),
            "--issuer-pins".into(),
            self.directory
                .join("issuer-pins.jsonl")
                .to_string_lossy()
                .into_owned(),
            "--require-intent".into(),
            "--format".into(),
            "json".into(),
        ]);
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.success(), summary["ok"] == true);
        summary
    }

    /// Rewrites `decided_at` (and `freshness_valid_until`, which must not be
    /// earlier) and re-signs with the attester key. This is what a
    /// compromised or misbehaving attester could do; an honest engine never
    /// records a decision outside the authority's validity.
    fn resigned_with_decided_at(&self, decided_at: &str) -> String {
        let mut evidence = self.evidence.clone();
        evidence.decided_at = Some(decided_at.into());
        evidence.freshness_valid_until =
            Some(format_rfc3339(parse(decided_at) + Duration::seconds(30)));
        evidence.context_hash = context_hash(&evidence);
        evidence.sign(&self.attester).unwrap();
        evidence.to_json().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_praetore-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn parse(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap()
}

/// The integrity hash covers every evidence field except `context_hash` and
/// `attester_signature`, in canonical JSON.
fn context_hash(evidence: &Evidence) -> String {
    let mut value = serde_json::to_value(evidence).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("context_hash");
    object.remove("attester_signature");
    let canonical = canonicalize_json(&serde_json::to_string(&value).unwrap()).unwrap();
    hex::encode(Sha256::digest(canonical))
}

#[test]
fn authority_expired_today_but_valid_at_decision_time_verifies() {
    let fixture = Fixture::new();
    assert!(OffsetDateTime::now_utc() > parse(AUTHORITY_NOT_AFTER));

    let summary = fixture.verify(&fixture.evidence.to_json().unwrap());
    assert_eq!(summary["code"], "OK", "{summary}");
    assert_eq!(summary["details"]["authority_verified"], true);
    assert_eq!(summary["details"]["authority_checked_at"], DECIDED_AT);
    assert_eq!(
        summary["details"]["authority_checked_at_source"],
        "receipt_decided_at"
    );
    assert_eq!(summary["details"]["intent_verified"], true);
    assert_eq!(summary["details"]["current_authorization"], false);
}

#[test]
fn decision_time_after_authority_expiry_fails() {
    let fixture = Fixture::new();
    let summary = fixture.verify(&fixture.resigned_with_decided_at("2026-02-01T00:00:01Z"));
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["code"], "AUTHORITY_EXPIRED", "{summary}");

    // The upper bound is inclusive, as in `Validity::is_active_at`.
    let summary = fixture.verify(&fixture.resigned_with_decided_at(AUTHORITY_NOT_AFTER));
    assert_eq!(summary["code"], "OK", "{summary}");
}

#[test]
fn decision_time_before_authority_not_before_fails() {
    let fixture = Fixture::new();
    let summary = fixture.verify(&fixture.resigned_with_decided_at("2026-01-09T23:59:59Z"));
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["code"], "AUTHORITY_EXPIRED", "{summary}");

    let summary = fixture.verify(&fixture.resigned_with_decided_at(AUTHORITY_NOT_BEFORE));
    assert_eq!(summary["code"], "OK", "{summary}");
}

#[test]
fn shifting_the_decision_time_without_the_attester_key_fails() {
    let fixture = Fixture::new();

    // Edit only `decided_at`: the integrity hash no longer matches.
    let mut value: Value = serde_json::from_str(&fixture.evidence.to_json().unwrap()).unwrap();
    value["decided_at"] = json!("2026-01-15T11:00:00Z");
    let summary = fixture.verify(&value.to_string());
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["code"], "EVIDENCE_FAIL", "{summary}");

    // Also recompute the unkeyed integrity hash: the attester signature
    // still covers the original `decided_at`. (An earlier time, so that
    // `freshness_valid_until` stays after it and the record stays well formed.)
    let mut shifted = fixture.evidence.clone();
    shifted.decided_at = Some("2026-01-15T11:00:00Z".into());
    shifted.context_hash = context_hash(&shifted);
    assert!(shifted.verify_integrity());
    let summary = fixture.verify(&serde_json::to_string(&shifted).unwrap());
    assert_eq!(summary["ok"], false);
    assert_eq!(summary["code"], "AUTH_FAIL", "{summary}");
}
