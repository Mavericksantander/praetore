use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{PraetoreError, Result};

/// Stable identifier for an agent.
///
/// This identifier is intentionally separate from cryptographic key material.
/// An AgentId identifies an agent; it does not, by itself, authenticate it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(Uuid);

impl AgentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

/// Public identity information associated with an agent.
///
/// `public_key` is represented as opaque bytes at this layer. The concrete
/// cryptographic algorithm belongs to the authentication layer and must not
/// be inferred from an arbitrary caller-supplied string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub public_key: Vec<u8>,
    pub key_algorithm: String,
}

impl AgentIdentity {
    pub fn new(id: AgentId, public_key: Vec<u8>, key_algorithm: impl Into<String>) -> Result<Self> {
        let identity = Self {
            id,
            public_key,
            key_algorithm: key_algorithm.into(),
        };

        identity.validate()?;

        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.public_key.is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "public key cannot be empty".into(),
            ));
        }

        if self.key_algorithm.trim().is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "key algorithm cannot be empty".into(),
            ));
        }

        if self.key_algorithm != self.key_algorithm.trim() {
            return Err(PraetoreError::InvalidIdentity(
                "key algorithm cannot have leading or trailing whitespace".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_unique_agent_ids() {
        let first = AgentId::new();
        let second = AgentId::new();

        assert_ne!(first, second);
    }

    #[test]
    fn agent_id_exposes_underlying_uuid() {
        let id = AgentId::new();

        assert!(!id.as_uuid().is_nil());
    }

    #[test]
    fn rejects_empty_public_key() {
        let result = AgentIdentity::new(AgentId::new(), Vec::new(), "ed25519");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_empty_algorithm() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_whitespace_algorithm() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "   ");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn rejects_algorithm_with_surrounding_whitespace() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], " ed25519 ");

        assert!(matches!(result, Err(PraetoreError::InvalidIdentity(_))));
    }

    #[test]
    fn accepts_valid_identity() {
        let identity =
            AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "ed25519").expect("valid identity");

        assert_eq!(identity.public_key, vec![1, 2, 3]);
        assert_eq!(identity.key_algorithm, "ed25519");
        assert!(identity.validate().is_ok());
    }

    #[test]
    fn validate_rejects_tampered_identity() {
        let mut identity = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "ed25519").unwrap();

        identity.public_key.clear();

        assert!(matches!(
            identity.validate(),
            Err(PraetoreError::InvalidIdentity(_))
        ));
    }
}
