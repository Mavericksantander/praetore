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

    #[error("policy integrity verification failed")]
    PolicyIntegrityFailed,

    #[error("evidence error: {0}")]
    EvidenceError(String),
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
            Self::PolicyEvaluationFailed(_) => ErrorKind::PolicyEvaluationFailure,
            Self::EvidenceError(_) => ErrorKind::EvidenceFailure,
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
        }
    }
}

pub type Result<T> = std::result::Result<T, PraetoreError>;
