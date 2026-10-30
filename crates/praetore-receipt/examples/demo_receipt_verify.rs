//! Receipt verification demo: issue, sign, verify, tamper, reject.
//!
//! DEMO/TEST ONLY. Every key in this file is derived from a fixed, public
//! seed and every record is fictitious. Never use these keys or this code to
//! sign anything real.
//!
//! Run with `./demo/verify-receipt.sh` or
//! `cargo run -p praetore-receipt --features signing --example demo_receipt_verify`.
//! Exits 0 only if the valid receipt verifies and every tampered copy is
//! rejected.

use std::{
    collections::HashSet,
    process::ExitCode,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use praetore_core::{
    Action, AgentId, AgentKeyFingerprint, AgentKeyPair, Authority, AuthorizationRequest,
    DecisionOutcome, EvidenceAttesterKey, FreshnessError, FreshnessLease, FreshnessProvider,
    HighAssuranceConfig, Policy, PolicyEffect, PolicyRule, ReplayGuard, ReplayGuardError,
    TrustedAuthorityIssuer, VerifiedPublicKey,
    authority::{AuthorityId, Validity},
    engine::{AuthorizationEngine, Clock, FixedClock},
};
use praetore_receipt::{
    AuthorizationStatus, ExecutionAttestation, ExecutionAttestationError,
    ExecutionAttestationSigner, ExecutionStatus, GatewayReceipt, verify_gateway_receipt_json,
};
use time::Duration;
use uuid::Uuid;

/// DEMO/TEST ONLY: fixed public seeds. Anyone can derive these private keys.
const DEMO_ONLY_EXECUTION_SEED: [u8; 32] = [0xD0; 32];
const DEMO_ONLY_AGENT_SEED: [u8; 32] = [0xD1; 32];
const DEMO_ONLY_ISSUER_SEED: [u8; 32] = [0xD2; 32];
const DEMO_ONLY_EVIDENCE_ATTESTER_SEED: [u8; 32] = [0xD3; 32];
const DEMO_ONLY_KEY_ID: &str = "DEMO-ONLY-not-for-real-use-v1";
const DEMO_TENANT: Uuid = Uuid::from_u128(0xDE40);
const NOW: &str = "2026-06-01T12:00:00Z";

type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

/// DEMO/TEST ONLY signer holding a key derived from a public seed.
struct DemoOnlyExecutionSigner(SigningKey);

impl ExecutionAttestationSigner for DemoOnlyExecutionSigner {
    fn key_id(&self) -> &str {
        DEMO_ONLY_KEY_ID
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExecutionAttestationError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

struct DemoReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl ReplayGuard for DemoReplayGuard {
    fn claim_once(&self, tenant: Uuid, agent: Uuid, request: Uuid) -> Result<(), ReplayGuardError> {
        let mut claims = self.0.lock().map_err(|_| ReplayGuardError::Unavailable)?;
        if claims.insert((tenant, agent, request)) {
            Ok(())
        } else {
            Err(ReplayGuardError::AlreadyClaimed)
        }
    }
}

struct DemoFreshness;

impl FreshnessProvider for DemoFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _policy_digest: &str,
        now: time::OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + Duration::minutes(1),
        })
    }

    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _authority_digest: &str,
        _policy_digest: &str,
        now: time::OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        Ok(FreshnessLease {
            valid_until: now + Duration::minutes(1),
        })
    }
}

/// Issues and signs a fictitious receipt. Returns the receipt JSON and the
/// execution public key; the private key is dropped when this returns.
fn issue_receipt() -> DemoResult<(String, [u8; 32])> {
    let clock = FixedClock::new(NOW);
    let now = clock.now();
    let validity = Validity {
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2027-01-01T00:00:00Z".into()),
    };
    let agent_key = AgentKeyPair::from_secret_bytes(&DEMO_ONLY_AGENT_SEED);
    let agent = agent_key.identity(AgentId::new());
    let issuer_key = AgentKeyPair::from_secret_bytes(&DEMO_ONLY_ISSUER_SEED);
    let mut authority = Authority::new(agent.id.clone(), "demo-issuer", vec!["report:read".into()])
        .with_constraint("tenant_id", DEMO_TENANT.to_string())
        .with_validity(validity.clone());
    authority.sign_for_agent(&issuer_key, &agent)?;

    let policy = Policy::new_v2(
        "demo-policy",
        1,
        vec![
            PolicyRule::new("allow-demo-read", "read_report", PolicyEffect::Allow)
                .with_capability("report:read"),
        ],
    );
    let policy_digest = policy.digest()?;
    let issuer_pin = TrustedAuthorityIssuer::new("demo-issuer", issuer_key.public_key())?
        .with_validity(validity)?;
    let config = HighAssuranceConfig::new(
        policy_digest.clone(),
        vec![issuer_pin],
        EvidenceAttesterKey::from_secret_bytes(&DEMO_ONLY_EVIDENCE_ATTESTER_SEED),
    )?
    .with_audience("demo-gateway")
    .with_replay_guard(Arc::new(DemoReplayGuard(Mutex::new(HashSet::new()))))
    .with_freshness_provider(Arc::new(DemoFreshness));
    let engine = AuthorizationEngine::production_with_clock(policy, config, clock)?;

    let action = Action::new(
        "read_report",
        Some("demo-report-0001".into()),
        serde_json::json!({"report": "fictitious-monthly-summary"}),
    )?
    .with_capability("report:read");
    let mut request = AuthorizationRequest::new(agent, authority, action)?;
    request.sign_intent_v2(
        &agent_key,
        "demo-gateway",
        now,
        now + Duration::minutes(1),
        &policy_digest,
    )?;
    let evidence = engine.evaluate(request)?;
    if evidence.decision.outcome != DecisionOutcome::Allow {
        return Err("demo policy did not allow the fictitious request".into());
    }

    let signer = DemoOnlyExecutionSigner(SigningKey::from_bytes(&DEMO_ONLY_EXECUTION_SEED));
    let public_key = signer.0.verifying_key().to_bytes();
    let output = serde_json::json!({"rows": 3, "note": "fictitious demo data"});
    let execution_attestation = ExecutionAttestation::create(
        &evidence,
        AuthorizationStatus::Allowed,
        ExecutionStatus::Executed,
        Some(&output),
        None,
        &signer,
    )?;
    let receipt = GatewayReceipt {
        evidence,
        authorization: AuthorizationStatus::Allowed,
        execution: ExecutionStatus::Executed,
        output: Some(output),
        execution_attestation,
    };
    Ok((serde_json::to_string_pretty(&receipt)?, public_key))
}

/// Verification path: receives only the receipt bytes and the public key.
fn verify(json: &str, public_key: &[u8; 32]) -> Result<(), ExecutionAttestationError> {
    let key = VerifiedPublicKey::from_bytes(public_key)
        .map_err(|_| ExecutionAttestationError::InvalidSignature)?;
    verify_gateway_receipt_json(json, &key, DEMO_ONLY_KEY_ID).map(|_| ())
}

/// Changes exactly one byte inside the first occurrence of `marker`, at
/// `offset` bytes after its start.
fn flip_one_byte(json: &str, marker: &str, offset: usize, new: u8) -> DemoResult<String> {
    let start = marker_position(json, marker)? + offset;
    let mut bytes = json.as_bytes().to_vec();
    if bytes[start] == new {
        return Err("tamper byte already has the new value".into());
    }
    bytes[start] = new;
    Ok(String::from_utf8(bytes)?)
}

/// Position of `marker`, searched only inside `execution_attestation` when the
/// marker is the attestation signature.
fn marker_position(json: &str, marker: &str) -> DemoResult<usize> {
    let from = if marker == ATTESTATION_SIGNATURE {
        json.find("\"execution_attestation\"")
            .ok_or("execution_attestation not found")?
    } else {
        0
    };
    Ok(from + json[from..].find(marker).ok_or("marker not found")?)
}

const ATTESTATION_SIGNATURE: &str = "\"signature\": \"";

fn check_rejected(
    step: &str,
    json: &str,
    key: &[u8; 32],
    expected: ExecutionAttestationError,
) -> bool {
    match verify(json, key) {
        Ok(()) => {
            println!("    FAIL  {step}: tampered receipt was ACCEPTED");
            false
        }
        Err(error) if error == expected => {
            println!("    PASS  {step}: rejected");
            println!("          error: {error:?} (\"{error}\")");
            true
        }
        Err(error) => {
            println!(
                "    FAIL  {step}: rejected with unexpected error {error:?}, expected {expected:?}"
            );
            false
        }
    }
}

fn run() -> DemoResult<bool> {
    println!("PRAETORE receipt verification demo");
    println!("!! DEMO/TEST ONLY: fixed public seeds, fictitious data. Never use these keys. !!");
    println!();

    println!("[1/4] Generate DEMO/TEST-ONLY Ed25519 key from fixed seed");
    let (receipt_json, public_key) = issue_receipt()?;
    println!("    key_id     : {DEMO_ONLY_KEY_ID}");
    println!("    public key : {}", hex::encode(public_key));
    println!();

    println!("[2/4] Issue and sign a fictitious receipt");
    println!(
        "    receipt    : {} bytes, authorization=allowed, execution=executed",
        receipt_json.len()
    );
    println!("    private key dropped; only public key and receipt are kept");
    println!();

    let mut ok = true;
    println!("[3/4] Verify with the public key only");
    match verify(&receipt_json, &public_key) {
        Ok(()) => println!("    PASS  valid receipt verified"),
        Err(error) => {
            println!("    FAIL  valid receipt rejected: {error:?} (\"{error}\")");
            ok = false;
        }
    }
    println!();

    println!("[4/4] Alter one byte and verify again");
    // 4a: one hex digit of the execution attestation signature ("signature": "<hex>").
    let sig_marker = ATTESTATION_SIGNATURE;
    let sig_offset = sig_marker.len() + 10;
    let original =
        receipt_json.as_bytes()[receipt_json.find(sig_marker).ok_or("no signature")? + sig_offset];
    let replacement = if original == b'0' { b'1' } else { b'0' };
    let tampered_sig = flip_one_byte(&receipt_json, sig_marker, sig_offset, replacement)?;
    ok &= check_rejected(
        "4a signature byte changed",
        &tampered_sig,
        &public_key,
        ExecutionAttestationError::InvalidSignature,
    );
    // 4b: the recorded output "rows": 3 -> 4.
    let tampered_output = flip_one_byte(&receipt_json, "\"rows\": 3", "\"rows\": ".len(), b'4')?;
    ok &= check_rejected(
        "4b output byte changed (rows 3 -> 4)",
        &tampered_output,
        &public_key,
        ExecutionAttestationError::InvalidPayload,
    );
    println!();

    Ok(ok)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            println!("RESULT: PASS (valid receipt accepted, tampered receipts rejected)");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("RESULT: FAIL (see steps above)");
            ExitCode::FAILURE
        }
        Err(error) => {
            println!("RESULT: FAIL (demo setup error: {error})");
            ExitCode::from(2)
        }
    }
}
