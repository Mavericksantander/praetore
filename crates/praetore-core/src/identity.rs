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
        if public_key.is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "public key cannot be empty".into(),
            ));
        }

        let key_algorithm = key_algorithm.into();

        if key_algorithm.trim().is_empty() {
            return Err(PraetoreError::InvalidIdentity(
                "key algorithm cannot be empty".into(),
            ));
        }

        Ok(Self {
            id,
            public_key,
            key_algorithm,
        })
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
    fn rejects_empty_public_key() {
        let result = AgentIdentity::new(AgentId::new(), Vec::new(), "ed25519");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_algorithm() {
        let result = AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "");

        assert!(result.is_err());
    }

    #[test]
    fn accepts_valid_identity() {
        let identity =
            AgentIdentity::new(AgentId::new(), vec![1, 2, 3], "ed25519").expect("valid identity");

        assert_eq!(identity.public_key, vec![1, 2, 3]);
        assert_eq!(identity.key_algorithm, "ed25519");
    }
}
