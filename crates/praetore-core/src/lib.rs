pub mod action;
pub mod authority;
pub mod authorization;
pub mod canonical;
pub mod decision;
pub mod engine;
pub mod error;
pub mod evidence;
pub mod freshness;
pub mod identity;
pub mod journal_chain;
pub mod key_rotation;
pub mod policy;
#[cfg(feature = "test-probe")]
pub mod probe;
pub mod replay;
pub mod storage_record;

pub use action::{Action, ClassifiedAction, MissionAction, SafetyAction};
pub use authority::{Authority, AuthorityId};
pub use authorization::{AuthorizationIntentV2, AuthorizationRequest};
pub use decision::{
    DecidedBy, Decision, DecisionOutcome, RecordedDecision, RecoveryObligation, Severity,
};
pub use engine::{
    AtomicEvaluationError, EvaluationMode, HighAssuranceConfig, TrustedAuthorityIssuer,
    TrustedClock, TrustedClockError,
};
pub use error::{ErrorKind, PraetoreError, Result};
pub use evidence::{Evidence, EvidenceAttesterKey};
pub use freshness::{FreshnessError, FreshnessLease, FreshnessProvider};
pub use identity::{AgentId, AgentIdentity, AgentKeyFingerprint, AgentKeyPair, VerifiedPublicKey};
pub use key_rotation::KeyRotationProof;
pub use policy::{
    ActionClass, ActionClassError, ActionClassProposal, ControlLoop, MatchOperator, Policy,
    PolicyCondition, PolicyDocumentError, PolicyEffect, PolicyLimit, PolicyRule, RecordedPolicy,
};
pub use replay::{
    AtomicAuthorizationCommit, AuthorizationCommitError, CompletedAuthorization, ReplayGuard,
    ReplayGuardError,
};
pub use storage_record::{
    RecordedMigration, StorageRecord, StorageRecordPayload, StorageRecordSigner,
};

/// Helpers for this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::{Action, ActionClass, MissionAction, Policy};

    /// Declares every action type a rule of `policy` names as Mission.
    pub(crate) fn mission_policy(mut policy: Policy) -> Policy {
        for rule in &policy.rules {
            policy
                .action_classes
                .entry(rule.action_type.clone())
                .or_insert(ActionClass::Mission);
        }
        policy
    }

    /// Wraps `action` as a mission action without a policy. The engine still
    /// checks it against its own policy's `action_classes`.
    pub(crate) fn mission(action: Action) -> MissionAction {
        MissionAction::classified(action)
    }
}

/// The Rust snippets of the policy documentation run as doc tests, so they
/// stay in step with the API (G7 changed it).
#[cfg(doctest)]
#[doc = include_str!("../../../docs/policy-language.md")]
pub struct PolicyLanguageDocTests;

#[cfg(doctest)]
#[doc = include_str!("../../../docs/crypto-and-policy.md")]
pub struct CryptoAndPolicyDocTests;
