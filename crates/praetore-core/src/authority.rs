use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    error::{PraetoreError, Result},
    identity::AgentId,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorityId(Uuid);

impl AuthorityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AuthorityId {
    fn default() -> Self {
        Self::new()
    }
}

/// A constraint limiting where or how an authority may be exercised.
///
/// Constraints are explicit data. They are not executable expressions.
/// Evaluation belongs to the authorization layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityConstraint {
    pub key: String,
    pub value: String,
}

impl AuthorityConstraint {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.key.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "authority constraint key cannot be empty".into(),
            ));
        }

        if self.value.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(format!(
                "authority constraint '{}' cannot have an empty value",
                self.key
            )));
        }

        Ok(())
    }
}

/// Validity interval for an authority.
///
/// `None` means unbounded on that side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

impl Validity {
    pub fn unbounded() -> Self {
        Self {
            not_before: None,
            not_after: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let not_before = self
            .not_before
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;

        let not_after = self.not_after.as_deref().map(parse_timestamp).transpose()?;

        if let (Some(not_before), Some(not_after)) = (not_before, not_after) {
            if not_after < not_before {
                return Err(PraetoreError::InvalidRequest(
                    "authority validity not_before cannot be after not_after".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn is_active_at(&self, now: OffsetDateTime) -> Result<bool> {
        let not_before = self
            .not_before
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;

        let not_after = self.not_after.as_deref().map(parse_timestamp).transpose()?;

        Ok(not_before.is_none_or(|ts| now >= ts) && not_after.is_none_or(|ts| now <= ts))
    }
}

/// A delegated authority granted to an agent.
///
/// Authority answers "what may this identity potentially do?"
/// Authorization answers "may it do this specific action now?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authority {
    pub id: AuthorityId,
    pub subject: AgentId,
    pub capabilities: Vec<String>,
    pub constraints: Vec<AuthorityConstraint>,
    pub issuer: String,
    pub validity: Validity,
    pub version: u32,
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime> {
    if value.trim().is_empty() {
        return Err(PraetoreError::InvalidRequest(
            "authority validity timestamp cannot be empty".into(),
        ));
    }

    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(|_| {
        PraetoreError::InvalidRequest("authority validity timestamp must be valid RFC 3339".into())
    })
}

impl Authority {
    pub fn new(subject: AgentId, issuer: impl Into<String>, capabilities: Vec<String>) -> Self {
        Self {
            id: AuthorityId::new(),
            subject,
            capabilities,
            constraints: Vec::new(),
            issuer: issuer.into(),
            validity: Validity::unbounded(),
            version: 1,
        }
    }

    pub fn permits(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }

    pub fn with_constraint(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.constraints.push(AuthorityConstraint::new(key, value));
        self
    }

    pub fn with_validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(PraetoreError::InvalidRequest(
                "authority issuer cannot be empty".into(),
            ));
        }

        if self.version == 0 {
            return Err(PraetoreError::InvalidRequest(
                "authority version must be greater than zero".into(),
            ));
        }

        for capability in &self.capabilities {
            if capability.trim().is_empty() {
                return Err(PraetoreError::InvalidRequest(
                    "authority capability cannot be empty".into(),
                ));
            }
        }

        for constraint in &self.constraints {
            constraint.validate()?;
        }

        self.validity.validate()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> AgentId {
        AgentId::new()
    }

    #[test]
    fn creates_unique_authority_ids() {
        let first = AuthorityId::new();
        let second = AuthorityId::new();

        assert_ne!(first, second);
    }

    #[test]
    fn authority_permits_declared_capability() {
        let authority = Authority::new(
            test_agent(),
            "praetore-root",
            vec!["read:data".into(), "write:data".into()],
        );

        assert!(authority.permits("read:data"));
        assert!(authority.permits("write:data"));
    }

    #[test]
    fn authority_rejects_undeclared_capability() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()]);

        assert!(!authority.permits("delete:data"));
    }

    #[test]
    fn authority_can_have_constraints() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["call:api".into()])
            .with_constraint("environment", "production");

        assert_eq!(authority.constraints.len(), 1);
        assert_eq!(authority.constraints[0].key, "environment");
        assert_eq!(authority.constraints[0].value, "production");
        assert!(authority.validate().is_ok());
    }

    #[test]
    fn authority_can_have_validity() {
        let validity = Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        };

        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_validity(validity.clone());

        assert_eq!(authority.validity, validity);
        assert!(authority.validate().is_ok());
    }

    #[test]
    fn authority_defaults_to_version_one() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()]);

        assert_eq!(authority.version, 1);
    }

    #[test]
    fn authority_rejects_empty_issuer() {
        let authority = Authority::new(test_agent(), "", vec!["read:data".into()]);

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_empty_capability() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["".into()]);

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_invalid_version() {
        let mut authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()]);

        authority.version = 0;

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_empty_constraint_key() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_constraint("", "production");

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_empty_constraint_value() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_constraint("environment", "");

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_empty_not_before() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_validity(Validity {
                not_before: Some(String::new()),
                not_after: None,
            });

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_invalid_timestamp() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_validity(Validity {
                not_before: Some("not-a-timestamp".into()),
                not_after: None,
            });

        assert!(authority.validate().is_err());
    }

    #[test]
    fn authority_rejects_invalid_validity_range() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_validity(Validity {
                not_before: Some("2027-01-01T00:00:00Z".into()),
                not_after: Some("2026-01-01T00:00:00Z".into()),
            });

        assert!(authority.validate().is_err());
    }
}
