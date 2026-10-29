use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    AuthenticationFailure,
    AuthorityVerificationFailure,
    AuthorityExpired,
    TrustStoreFailure,
    IntentInvalid,
    InvalidRequest,
    PolicyDenied,
    PolicyIntegrityFailure,
    PolicyEvaluationFailure,
    EvidenceFailure,
    ReplayDetected,
    ReplayGuardFailure,
    FreshnessRevoked,
    FreshnessUnknown,
    FreshnessExpired,
    FreshnessUnavailable,
    FreshnessInvalid,
    FreshnessLeaseTooLong,
    TrustedClockUnavailable,
}

#[derive(Debug, Error)]
pub enum PraetoreError {
    #[error("identity verification failed")]
    IdentityVerificationFailed,

    #[error("invalid identity: {0}")]
    InvalidIdentity(String),

    #[error("authority verification failed")]
    AuthorityVerificationFailed,

    #[error("authority expired or is not yet valid")]
    AuthorityExpired,

    #[error("trust store verification failed")]
    TrustStoreFailure,

    #[error("request intent verification failed")]
    IntentInvalid,

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("invalid authorization request: {0}")]
    InvalidRequest(String),

    #[error("policy evaluation failed: {0}")]
    PolicyEvaluationFailed(String),

    /// A policy document exceeds a size or complexity limit and was rejected
    /// as a whole (never partially applied).
    #[error("policy limit exceeded: {limit} (maximum {max})")]
    PolicyLimitExceeded {
        limit: crate::policy::PolicyLimit,
        max: usize,
    },

    #[error("policy integrity verification failed")]
    PolicyIntegrityFailed,

    #[error("evidence error: {0}")]
    EvidenceError(String),

    #[error("authorization request has already been used")]
    ReplayDetected,

    #[error("replay protection storage is unavailable")]
    ReplayGuardUnavailable,

    #[error("trusted clock is unavailable or unhealthy")]
    TrustedClockUnavailable,

    #[error("freshness check failed")]
    FreshnessCheckFailed(crate::freshness::FreshnessError),
}

impl PraetoreError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::IdentityVerificationFailed | Self::InvalidIdentity(_) => {
                ErrorKind::AuthenticationFailure
            }
            Self::AuthorityVerificationFailed => ErrorKind::AuthorityVerificationFailure,
            Self::AuthorityExpired => ErrorKind::AuthorityExpired,
            Self::TrustStoreFailure => ErrorKind::TrustStoreFailure,
            Self::IntentInvalid => ErrorKind::IntentInvalid,
            Self::AuthorizationDenied(_) => ErrorKind::PolicyDenied,
            Self::InvalidRequest(_) => ErrorKind::InvalidRequest,
            Self::PolicyIntegrityFailed => ErrorKind::PolicyIntegrityFailure,
            Self::PolicyEvaluationFailed(_) | Self::PolicyLimitExceeded { .. } => {
                ErrorKind::PolicyEvaluationFailure
            }
            Self::EvidenceError(_) => ErrorKind::EvidenceFailure,
            Self::ReplayDetected => ErrorKind::ReplayDetected,
            Self::ReplayGuardUnavailable => ErrorKind::ReplayGuardFailure,
            Self::TrustedClockUnavailable => ErrorKind::TrustedClockUnavailable,
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::Revoked) => {
                ErrorKind::FreshnessRevoked
            }
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::Unknown) => {
                ErrorKind::FreshnessUnknown
            }
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::Expired) => {
                ErrorKind::FreshnessExpired
            }
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::Unavailable) => {
                ErrorKind::FreshnessUnavailable
            }
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::InvalidResponse) => {
                ErrorKind::FreshnessInvalid
            }
            Self::FreshnessCheckFailed(crate::freshness::FreshnessError::LeaseTooLong) => {
                ErrorKind::FreshnessLeaseTooLong
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self.kind() {
            ErrorKind::AuthenticationFailure => "AUTH_FAIL",
            ErrorKind::AuthorityVerificationFailure => "AUTHORITY_VERIFY_FAIL",
            ErrorKind::AuthorityExpired => "AUTHORITY_EXPIRED",
            ErrorKind::TrustStoreFailure => "TRUST_STORE_FAIL",
            ErrorKind::IntentInvalid => "INTENT_INVALID",
            ErrorKind::InvalidRequest => "INVALID_REQUEST",
            ErrorKind::PolicyDenied => "POLICY_DENY",
            ErrorKind::PolicyIntegrityFailure => "POLICY_INTEGRITY_FAIL",
            ErrorKind::PolicyEvaluationFailure => "POLICY_EVALUATION_FAIL",
            ErrorKind::EvidenceFailure => "EVIDENCE_FAIL",
            ErrorKind::ReplayDetected => "REPLAY_DETECTED",
            ErrorKind::ReplayGuardFailure => "REPLAY_GUARD_FAIL",
            ErrorKind::FreshnessRevoked => "FRESHNESS_REVOKED",
            ErrorKind::FreshnessUnknown => "FRESHNESS_UNKNOWN",
            ErrorKind::FreshnessExpired => "FRESHNESS_EXPIRED",
            ErrorKind::FreshnessUnavailable => "FRESHNESS_UNAVAILABLE",
            ErrorKind::FreshnessInvalid => "FRESHNESS_INVALID",
            ErrorKind::FreshnessLeaseTooLong => "FRESHNESS_LEASE_TOO_LONG",
            ErrorKind::TrustedClockUnavailable => "TRUSTED_CLOCK_UNAVAILABLE",
        }
    }
}

pub type Result<T> = std::result::Result<T, PraetoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_errors_have_stable_non_leaky_codes() {
        let replay = PraetoreError::ReplayDetected;
        assert_eq!(replay.kind(), ErrorKind::ReplayDetected);
        assert_eq!(replay.code(), "REPLAY_DETECTED");
        assert_eq!(
            replay.to_string(),
            "authorization request has already been used"
        );

        let unavailable = PraetoreError::ReplayGuardUnavailable;
        assert_eq!(unavailable.kind(), ErrorKind::ReplayGuardFailure);
        assert_eq!(unavailable.code(), "REPLAY_GUARD_FAIL");
        assert_eq!(
            unavailable.to_string(),
            "replay protection storage is unavailable"
        );
    }

    #[test]
    fn trusted_clock_failures_have_a_stable_non_leaky_code() {
        let error = PraetoreError::TrustedClockUnavailable;
        assert_eq!(error.kind(), ErrorKind::TrustedClockUnavailable);
        assert_eq!(error.code(), "TRUSTED_CLOCK_UNAVAILABLE");
        assert_eq!(
            error.to_string(),
            "trusted clock is unavailable or unhealthy"
        );
    }

    #[test]
    fn freshness_failures_have_stable_machine_codes() {
        let cases = [
            (
                crate::freshness::FreshnessError::Revoked,
                "FRESHNESS_REVOKED",
            ),
            (
                crate::freshness::FreshnessError::Unknown,
                "FRESHNESS_UNKNOWN",
            ),
            (
                crate::freshness::FreshnessError::Expired,
                "FRESHNESS_EXPIRED",
            ),
            (
                crate::freshness::FreshnessError::Unavailable,
                "FRESHNESS_UNAVAILABLE",
            ),
            (
                crate::freshness::FreshnessError::InvalidResponse,
                "FRESHNESS_INVALID",
            ),
            (
                crate::freshness::FreshnessError::LeaseTooLong,
                "FRESHNESS_LEASE_TOO_LONG",
            ),
        ];

        for (error, expected_code) in cases {
            assert_eq!(
                PraetoreError::FreshnessCheckFailed(error).code(),
                expected_code
            );
        }
    }
}
