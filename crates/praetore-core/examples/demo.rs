//! End-to-end demo of the PRAETORE kernel for a short walkthrough.
//!
//! A simulated AI agent attempts three actions. The kernel decides each one
//! (HighAssurance engine, signed receipts), the receipts are exported as a
//! hash-linked JSONL chain, the chain is verified, and two altered copies are
//! rejected. Every step uses the public `praetore-core` API; nothing here
//! imitates a capability the kernel does not have.
//!
//! Run from the repository root:
//!
//! ```text
//! cargo run --locked -p praetore-core --example demo [OUTPUT_DIR]
//! ```
//!
//! OUTPUT_DIR defaults to `target/praetore-demo`. It receives the chain, the
//! attester public key and the policy, so the chain can also be checked with
//! the separate `praetore-verify` binary (see docs/DEMO.md).
//!
//! Terminal output is in Spanish (audience of the walkthrough); code and docs
//! are in English like the rest of the repository.
//!
//! The process exits non-zero if any decision or verification differs from
//! the expected one, so CI runs it as a check.

use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use praetore_core::{
    Action, AgentId, AgentIdentity, AgentKeyFingerprint, AgentKeyPair, Authority,
    AuthorizationRequest, DecidedBy, DecisionOutcome, Evidence, EvidenceAttesterKey,
    FreshnessError, FreshnessLease, FreshnessProvider, HighAssuranceConfig, Policy,
    PolicyCondition, PolicyEffect, PolicyRule, ReplayGuard, ReplayGuardError,
    TrustedAuthorityIssuer,
    authority::{AuthorityId, Validity},
    engine::{AuthorizationEngine, Clock, SystemClock},
    journal_chain::{ChainExporter, verify_chain},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

type DemoResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const AUDIENCE: &str = "demo-gateway";
const REFUND_LIMIT_CLP: u64 = 500_000;

/// In-memory replay guard: rejects a reused request id within this process.
/// Not durable across restarts. Production deployments use the Postgres
/// guard (`praetore-replay-postgres`).
#[derive(Default)]
struct InMemoryReplayGuard(Mutex<HashSet<(Uuid, Uuid, Uuid)>>);

impl ReplayGuard for InMemoryReplayGuard {
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

/// Fixed one-minute lease with no revocation source: a revoked agent key or
/// authority would still be accepted. Same behavior as the local mode of
/// `praetore-mcp`. Not suitable for production.
struct FixedLeaseFreshness;

impl FreshnessProvider for FixedLeaseFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _policy_digest: &str,
        _now: OffsetDateTime,
    ) -> std::result::Result<FreshnessLease, FreshnessError> {
        // Only the authority-bound check is used by HighAssurance.
        Err(FreshnessError::InvalidResponse)
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

struct Attempt {
    label: &'static str,
    description: String,
    action: Action,
    expected: DecisionOutcome,
    expected_by: DecidedBy,
}

fn rule(rule_id: &str) -> DecidedBy {
    DecidedBy::Rule {
        rule_id: rule_id.into(),
    }
}

fn demo_policy() -> Policy {
    Policy::new_v2(
        "demo-payments-policy",
        1,
        vec![
            PolicyRule::new("allow-read-accounts", "read_account", PolicyEffect::Allow)
                .with_capability("accounts:read"),
            PolicyRule::new(
                "deny-refund-over-limit",
                "create_refund",
                PolicyEffect::Deny,
            )
            .with_parameter_condition(PolicyCondition::greater_than(
                "amount_clp",
                serde_json::json!(REFUND_LIMIT_CLP),
            )),
            PolicyRule::new("allow-refunds", "create_refund", PolicyEffect::Allow)
                .with_capability("refunds:create"),
            PolicyRule::new(
                "allow-customer-export",
                "export_customer_data",
                PolicyEffect::Allow,
            )
            .with_capability("customers:export"),
        ],
    )
    .with_mission_actions(["read_account", "create_refund", "export_customer_data"])
}

fn attempts() -> DemoResult<Vec<Attempt>> {
    Ok(vec![
        Attempt {
            label: "1",
            description: "leer el saldo de la cuenta acct-1029".into(),
            action: Action::new(
                "read_account",
                Some("acct-1029".into()),
                serde_json::json!({"fields": ["balance"]}),
            )?
            .with_capability("accounts:read"),
            expected: DecisionOutcome::Allow,
            expected_by: rule("allow-read-accounts"),
        },
        Attempt {
            label: "2",
            description: format!(
                "reembolsar 2.500.000 CLP (límite de la política: {} CLP)",
                "500.000"
            ),
            action: Action::new(
                "create_refund",
                Some("order-7731".into()),
                serde_json::json!({"amount_clp": 2_500_000, "currency": "CLP"}),
            )?
            .with_capability("refunds:create"),
            expected: DecisionOutcome::Deny,
            expected_by: rule("deny-refund-over-limit"),
        },
        Attempt {
            label: "3",
            description: "exportar la base de clientes (capacidad customers:export)".into(),
            action: Action::new(
                "export_customer_data",
                Some("customers-all".into()),
                serde_json::json!({"format": "csv"}),
            )?
            .with_capability("customers:export"),
            expected: DecisionOutcome::Deny,
            expected_by: DecidedBy::engine_guard("authority_capability"),
        },
    ])
}

fn outcome_es(outcome: DecisionOutcome) -> &'static str {
    match outcome {
        DecisionOutcome::Allow => "ALLOW (permitida)",
        DecisionOutcome::Deny => "DENY (denegada)",
        DecisionOutcome::RequireApproval => "REQUIRE_APPROVAL (requiere aprobación)",
    }
}

fn decided_by_es(decided_by: &DecidedBy) -> String {
    match decided_by {
        DecidedBy::Rule { rule_id } => format!("regla de política `{rule_id}`"),
        DecidedBy::UnboundRule { rule_id } => {
            format!("regla `{rule_id}` sin capacidad vinculada (denegada por defecto)")
        }
        DecidedBy::DefaultDeny => "ninguna regla coincide: denegación por defecto".into(),
        DecidedBy::EngineGuard { guard } => format!("control del motor `{guard}`"),
    }
}

fn check(condition: bool, message: &str) -> DemoResult<()> {
    if condition {
        Ok(())
    } else {
        Err(format!("la demo no obtuvo el resultado esperado: {message}").into())
    }
}

fn rfc3339(instant: OffsetDateTime) -> DemoResult<String> {
    Ok(instant.format(&Rfc3339)?)
}

fn section(title: &str) {
    println!("\n== {title}");
}

fn main() -> DemoResult<()> {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/praetore-demo"));
    fs::create_dir_all(&out_dir)?;

    println!("PRÆTORE: demo del kernel de autorización determinista");
    println!();
    println!("AVISO: configuración de demostración, NO apta para producción.");
    println!("  - Replay guard en memoria: no sobrevive a un reinicio del proceso.");
    println!("  - Frescura con lease fijo de 1 minuto y SIN fuente de revocación:");
    println!("    una llave o autoridad revocada seguiría siendo aceptada.");
    println!("  - Llaves generadas al vuelo; los hashes cambian en cada ejecución.");

    // --- Setup: issuer, agent, authority, policy, attester. ---------------
    let now = SystemClock.now();
    let validity = Validity {
        not_before: Some(rfc3339(now - Duration::hours(1))?),
        not_after: Some(rfc3339(now + Duration::hours(1))?),
    };

    let issuer_key = AgentKeyPair::generate();
    let agent_key = AgentKeyPair::generate();
    let agent: AgentIdentity = agent_key.identity(AgentId::new());
    let granted = vec!["accounts:read".to_string(), "refunds:create".to_string()];
    let mut authority = Authority::new(agent.id.clone(), "demo-issuer", granted.clone())
        .with_validity(validity.clone());
    authority.sign_for_agent(&issuer_key, &agent)?;
    let issuer_pin = TrustedAuthorityIssuer::new("demo-issuer", issuer_key.public_key())?
        .with_validity(validity)?;

    let policy = demo_policy();
    let policy_digest = policy.digest()?;
    let attester = EvidenceAttesterKey::generate();
    let attester_public_key = attester.public_key()?;

    section("Configuración");
    println!(
        "Agente simulado: \"agente-soporte\" (id {})",
        agent.id.as_uuid()
    );
    println!(
        "Autoridad firmada por el emisor `demo-issuer`: {}",
        granted.join(", ")
    );
    println!(
        "Política `demo-payments-policy` v1 (digest {}…):",
        &policy_digest[..16]
    );
    println!("  - allow-read-accounts     read_account          requiere accounts:read");
    println!("  - deny-refund-over-limit  create_refund         si amount_clp > 500000");
    println!("  - allow-refunds           create_refund         requiere refunds:create");
    println!("  - allow-customer-export   export_customer_data  requiere customers:export");

    let config = HighAssuranceConfig::new(policy_digest.clone(), vec![issuer_pin], attester)?
        .with_audience(AUDIENCE)
        .with_replay_guard(Arc::new(InMemoryReplayGuard::default()))
        .with_freshness_provider(Arc::new(FixedLeaseFreshness));
    let engine = AuthorizationEngine::production_with_clock(policy.clone(), config, SystemClock)?;

    // --- Decisions. --------------------------------------------------------
    section("El agente intenta tres acciones");
    let mut receipts: Vec<Evidence> = Vec::new();
    for attempt in attempts()? {
        let action = policy.classify(attempt.action)?.into_mission()?;
        let mut request = AuthorizationRequest::new(agent.clone(), authority.clone(), action)?;
        let issued_at = SystemClock.now();
        request.sign_intent_v2(
            &agent_key,
            AUDIENCE,
            issued_at,
            issued_at + Duration::minutes(1),
            &policy_digest,
        )?;
        let evidence = engine.evaluate(request)?;
        let decision = &evidence.decision;
        let decided_by = decision
            .decided_by()
            .ok_or("el recibo no registra decided_by")?;

        println!();
        println!(
            "[{}] El agente pide: {}",
            attempt.label, attempt.description
        );
        println!("    Decisión:  {}", outcome_es(decision.outcome));
        println!("    Causa:     {}", decided_by_es(decided_by));
        println!("    Motivo:    {}", decision.reason);
        println!(
            "    Recibo:    {} (firmado por el atestador)",
            evidence.evidence_id
        );
        if matches!(decided_by, DecidedBy::EngineGuard { guard } if guard == "authority_capability")
        {
            println!("    Nota:      aquí no decide la política. La política permitiría la");
            println!("               exportación a quien tenga customers:export, pero este");
            println!("               agente nunca recibió esa autoridad: \"la política lo");
            println!("               prohíbe\" (caso 2) no es lo mismo que \"el agente nunca");
            println!("               tuvo esa autoridad\" (caso 3).");
        }

        check(
            decision.outcome == attempt.expected,
            &format!("caso {}: decisión {:?}", attempt.label, decision.outcome),
        )?;
        check(
            decided_by == &attempt.expected_by,
            &format!("caso {}: causa {decided_by:?}", attempt.label),
        )?;
        evidence.verify_attester_signature(&attester_public_key)?;
        receipts.push(evidence);
    }

    // --- Hash-linked evidence chain. --------------------------------------
    section("Registro de evidencia encadenado por hash");
    let mut exporter = ChainExporter::new(&attester_public_key);
    for evidence in &receipts {
        exporter.push(evidence)?;
    }
    let (chain, head) = exporter.finish()?;
    for (index, line) in chain.lines().enumerate() {
        let entry: serde_json::Value = serde_json::from_str(line)?;
        let prev = entry["prev"].as_str().unwrap_or_default();
        let outcome = entry["evidence"]["decision"]["outcome"]
            .as_str()
            .unwrap_or_default();
        println!(
            "  seq {index}  prev {}…  {:<5}  {}",
            &prev[..16],
            outcome,
            entry["evidence"]["action"]["action_type"]
                .as_str()
                .unwrap_or_default()
        );
    }
    println!("  head (último eslabón): {head}", head = head.head);

    let chain_path = out_dir.join("journal.jsonl");
    let pin_path = out_dir.join("attester-public-key.hex");
    let policy_path = out_dir.join("policy.json");
    let head_path = out_dir.join("expected-head.txt");
    fs::write(&chain_path, &chain)?;
    fs::write(&pin_path, hex::encode(attester_public_key.as_bytes()))?;
    fs::write(&policy_path, serde_json::to_string_pretty(&policy)?)?;
    fs::write(&head_path, head.head.to_hex())?;

    // --- Verification and tamper detection. -------------------------------
    section("Verificación de la cadena");
    let verified = verify_chain(&chain, &attester_public_key, None, Some(&head.head))?;
    check(verified == head, "la cadena original no verifica")?;
    println!(
        "  Original: OK ({} recibos, firmas válidas, head coincide)",
        verified.entries
    );

    let tampered_outcome = tamper_outcome(&chain)?;
    let error = verify_chain(
        &tampered_outcome,
        &attester_public_key,
        None,
        Some(&head.head),
    )
    .err()
    .ok_or("la alteración del recibo 2 no fue detectada")?;
    println!("  Alteración A: en el recibo 2 se cambia \"Deny\" por \"Allow\".");
    println!("    -> RECHAZADA [{}]: {error}", error.code());

    let removed_line = remove_line(&chain, 1);
    let error = verify_chain(&removed_line, &attester_public_key, None, Some(&head.head))
        .err()
        .ok_or("la eliminación del recibo 2 no fue detectada")?;
    println!("  Alteración B: se borra el recibo 2 de la cadena.");
    println!("    -> RECHAZADA [{}]: {error}", error.code());
    let tampered_path = out_dir.join("journal-tampered.jsonl");
    fs::write(&tampered_path, &tampered_outcome)?;

    section("Archivos para verificar con un binario independiente");
    println!("  {}", chain_path.display());
    println!("  {}", tampered_path.display());
    println!("  {}", pin_path.display());
    println!("  {}", policy_path.display());
    println!("  {}", head_path.display());
    println!();
    println!("  cargo run --locked -q -p praetore-verify -- journal \\");
    println!("    --journal {} \\", chain_path.display());
    println!("    --attester-pin {} \\", pin_path.display());
    println!("    --policy {} \\", policy_path.display());
    println!("    --expected-head \"$(cat {})\"", head_path.display());
    println!();
    println!("Demo completa: 3 decisiones, cadena verificada, 2 alteraciones detectadas.");
    Ok(())
}

/// Copy of the chain where the second receipt's outcome reads `Allow`.
/// Only the receipt bytes change; seq and prev stay as they were.
fn tamper_outcome(chain: &str) -> DemoResult<String> {
    let mut lines: Vec<String> = chain.lines().map(str::to_owned).collect();
    let target = lines
        .get_mut(1)
        .ok_or("la cadena tiene menos de 2 líneas")?;
    let altered = target.replace("\"outcome\":\"Deny\"", "\"outcome\":\"Allow\"");
    if altered == *target {
        return Err("el recibo 2 no contiene \"outcome\":\"Deny\"".into());
    }
    *target = altered;
    Ok(lines.join("\n") + "\n")
}

fn remove_line(chain: &str, index: usize) -> String {
    let mut out = String::new();
    for (position, line) in chain.lines().enumerate() {
        if position != index {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
