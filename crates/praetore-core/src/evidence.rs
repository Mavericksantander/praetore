use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    action::Action,
    authority::Authority,
    decision::{Decision, DecisionOutcome},
    identity::AgentIdentity,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: Uuid,
    pub request_id: Uuid,
    pub agent: AgentIdentity,
    pub authority: Authority,
    pub action: Action,
    pub decision: Decision,
    pub trace_id: Option<String>,
    pub context_hash: String,
}

impl Evidence {
    pub fn new(
        request_id: Uuid,
        agent: AgentIdentity,
        authority: Authority,
        action: Action,
        decision: Decision,
        trace_id: Option<String>,
    ) -> Self {
        let context_hash = Self::compute_context_hash(
            &request_id,
            &agent,
            &authority,
            &action,
            &decision,
            &trace_id,
        );

        Self {
            evidence_id: Uuid::new_v4(),
            request_id,
            agent,
            authority,
            action,
            decision,
            trace_id,
            context_hash,
        }
    }

    pub fn outcome(&self) -> DecisionOutcome {
        self.decision.outcome
    }

    /// Verifies the integrity of the evidence payload.
    ///
    /// This verifies that the evidence contents still correspond to the
    /// recorded SHA-256 context hash. It does not authenticate the issuer
    /// cryptographically and does not provide non-repudiation.
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_context_hash(
            &self.request_id,
            &self.agent,
            &self.authority,
            &self.action,
            &self.decision,
            &self.trace_id,
        );

        self.context_hash == expected
    }

    /// Backwards-compatible alias for `verify_integrity`.
    pub fn verify(&self) -> bool {
        self.verify_integrity()
    }

    fn compute_context_hash(
        request_id: &Uuid,
        agent: &AgentIdentity,
        authority: &Authority,
        action: &Action,
        decision: &Decision,
        trace_id: &Option<String>,
    ) -> String {
        let payload = serde_json::json!({
            "request_id": request_id,
            "agent": agent,
            "authority": authority,
            "action": action,
            "decision": decision,
            "trace_id": trace_id,
        });

        let serialized = serde_json::to_vec(&payload).expect("evidence serialization must succeed");

        let digest = Sha256::digest(serialized);

        hex::encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        decision::{Decision, DecisionContribution, DecisionOutcome},
        identity::{AgentId, AgentIdentity},
    };
    use serde_json::json;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_authority(agent: &AgentIdentity) -> Authority {
        Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()])
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap()
    }

    fn test_decision() -> Decision {
        Decision::allow("policy permitted action")
    }

    fn test_evidence() -> Evidence {
        let agent = test_agent();
        let authority = test_authority(&agent);

        Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            None,
        )
    }

    #[test]
    fn creates_evidence_with_unique_id() {
        let first = test_evidence();
        let second = test_evidence();

        assert_ne!(first.evidence_id, second.evidence_id);
    }

    #[test]
    fn evidence_verifies_after_creation() {
        let evidence = test_evidence();

        assert!(evidence.verify());
        assert!(evidence.verify_integrity());
    }

    #[test]
    fn evidence_exposes_decision_outcome() {
        let evidence = test_evidence();

        assert_eq!(evidence.outcome(), DecisionOutcome::Allow);
    }

    #[test]
    fn trace_id_is_preserved_in_evidence() {
        let agent = test_agent();
        let authority = test_authority(&agent);

        let evidence = Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            Some("trace-001".into()),
        );

        assert_eq!(evidence.trace_id.as_deref(), Some("trace-001"));
        assert!(evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_trace_id_invalidates_evidence() {
        let agent = test_agent();
        let authority = test_authority(&agent);

        let mut evidence = Evidence::new(
            Uuid::new_v4(),
            agent,
            authority,
            test_action(),
            test_decision(),
            Some("trace-001".into()),
        );

        evidence.trace_id = Some("trace-999".into());

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_action_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.action = Action::new(
            "delete_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_action_parameters_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.action.parameters = json!({
            "table": "secrets"
        });

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_request_id_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.request_id = Uuid::new_v4();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_agent_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.agent.public_key = b"tampered-public-key".to_vec();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_agent_algorithm_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.agent.key_algorithm = "rsa".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.authority.issuer = "tampered-issuer".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_constraints_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence
            .authority
            .constraints
            .push(crate::authority::AuthorityConstraint::new(
                "environment",
                "production",
            ));

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_authority_validity_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.authority.validity.not_after = Some("2027-01-01T00:00:00Z".into());

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.decision = Decision::deny("policy rejected action");

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_reason_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.decision.reason = "tampered reason".into();

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn tampering_with_decision_contributions_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence
            .decision
            .contributions
            .push(DecisionContribution::new(
                "tampered-rule",
                DecisionOutcome::Deny,
                "tampered contribution",
            ));

        assert!(!evidence.verify_integrity());
    }

    #[test]
    fn evidence_id_is_not_part_of_integrity_hash() {
        let mut evidence = test_evidence();
        let original_hash = evidence.context_hash.clone();

        evidence.evidence_id = Uuid::new_v4();

        assert_eq!(evidence.context_hash, original_hash);
        assert!(evidence.verify_integrity());
    }
}
