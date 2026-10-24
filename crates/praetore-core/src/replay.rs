use std::fmt;
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
/// Implementations must make the claim atomic across every engine instance
/// sharing the same authorization domain. Claims must not expire automatically:
/// removing an entry can make an old signed request usable again. If storage is
/// unavailable or full, implementations must return `Unavailable`.
pub trait ReplayGuard: Send + Sync {
    fn claim_once(
        &self,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> std::result::Result<(), ReplayGuardError>;
}
