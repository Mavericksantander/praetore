use crate::{evidence::Evidence, identity::VerifiedPublicKey};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayGuardError {
    AlreadyClaimed,
    Unavailable,
}

impl fmt::Display for ReplayGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClaimed => f.write_str("request was already claimed"),
            Self::Unavailable => f.write_str("replay guard is unavailable"),
        }
    }
}

/// Caller-owned, durable, atomic one-time request-ID storage.
///
/// `tenant_id` is derived from the signed authority. The nil UUID represents
/// an authority without a tenant claim and keeps those requests in one
/// unscoped namespace. Implementations must make the claim atomic across every
/// engine instance sharing a tenant namespace. Claims must not expire
/// automatically: removing an entry can make an old signed request usable
/// again. If storage is unavailable or full, implementations must return
/// `Unavailable`.
pub trait ReplayGuard: Send + Sync {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> std::result::Result<(), ReplayGuardError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthorizationCommitError {
    #[error("authorization identity was already committed")]
    AlreadyCommitted,
    #[error("authorization identity conflicts with different request content")]
    ConflictingRequest,
    #[error("replay claim exists without a matching authorization record")]
    OrphanedReplayClaim,
    #[error("authorization commit storage is unavailable")]
    Unavailable,
    #[error("persisted authorization record is invalid")]
    InvalidRecord,
    #[error("no matching committed authorization record exists")]
    NotFound,
}

/// Unforgeable process-local marker that evidence has just completed the
/// configured HighAssurance evaluation path.
///
/// Its constructor and evidence field are private. Persisted or historical
/// [`Evidence`] values cannot be passed directly to an atomic commit provider.
pub struct CompletedAuthorization {
    evidence: Evidence,
}

impl CompletedAuthorization {
    pub(crate) fn new(evidence: Evidence) -> Self {
        Self { evidence }
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

/// Atomically persists a completed HighAssurance authorization with its
/// one-time replay claim.
///
/// `commit_authorization` must commit the replay claim and the exact signed
/// evidence as one durable operation. An implementation must never infer
/// authorization from a replay claim alone. On an uncertain commit result,
/// callers may use `verify_committed_authorization` to confirm that the
/// matching evidence and claim are both durable and still in the initial
/// non-dispatched state.
pub trait AtomicAuthorizationCommit: Send + Sync {
    fn commit_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> std::result::Result<(), AuthorizationCommitError>;

    fn verify_committed_authorization(
        &self,
        authorization: &CompletedAuthorization,
        trusted_attester: &VerifiedPublicKey,
    ) -> std::result::Result<(), AuthorizationCommitError>;
}
