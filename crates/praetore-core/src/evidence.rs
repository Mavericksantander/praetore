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

    pub fn verify(&self) -> bool {
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

        let canonical =
            serde_json::to_vec(&payload).expect("evidence serialization must be deterministic");

        let digest = Sha256::digest(canonical);

        hex::encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        decision::Decision,
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
        assert!(evidence.verify());
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

        assert!(!evidence.verify());
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

        assert!(!evidence.verify());
    }

    #[test]
    fn tampering_with_request_id_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.request_id = Uuid::new_v4();

        assert!(!evidence.verify());
    }

    #[test]
    fn tampering_with_agent_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.agent.public_key = b"tampered-public-key".to_vec();

        assert!(!evidence.verify());
    }

    #[test]
    fn tampering_with_authority_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.authority.issuer = "tampered-issuer".into();

        assert!(!evidence.verify());
    }

    #[test]
    fn tampering_with_decision_invalidates_evidence() {
        let mut evidence = test_evidence();

        evidence.decision = Decision::deny("policy rejected action");

        assert!(!evidence.verify());
    }
}
