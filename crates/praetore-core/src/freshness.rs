use std::fmt;

use time::OffsetDateTime;

use crate::{authority::AuthorityId, identity::AgentKeyFingerprint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessLease {
    pub valid_until: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    Revoked,
    Unknown,
    Expired,
    Unavailable,
    InvalidResponse,
    LeaseTooLong,
}

impl FreshnessError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Revoked => "FRESHNESS_REVOKED",
            Self::Unknown => "FRESHNESS_UNKNOWN",
            Self::Expired => "FRESHNESS_EXPIRED",
            Self::Unavailable => "FRESHNESS_UNAVAILABLE",
            Self::InvalidResponse => "FRESHNESS_INVALID",
            Self::LeaseTooLong => "FRESHNESS_LEASE_TOO_LONG",
        }
    }
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for FreshnessError {}

pub trait FreshnessProvider: Send + Sync {
    fn check(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &AuthorityId,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> std::result::Result<FreshnessLease, FreshnessError>;

    /// Checks current state for the exact canonical authority payload.
    ///
    /// Implementations that do not bind freshness to authority content remain
    /// source-compatible but fail closed in HighAssurance.
    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _authority_digest: &str,
        _policy_digest: &str,
        _now: OffsetDateTime,
    ) -> std::result::Result<FreshnessLease, FreshnessError> {
        Err(FreshnessError::InvalidResponse)
    }
}
