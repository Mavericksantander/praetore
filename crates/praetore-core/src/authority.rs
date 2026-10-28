use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    canonical::{canonical_json, parse_json_rejecting_duplicates},
    error::{PraetoreError, Result},
    identity::{AgentId, AgentIdentity, AgentKeyPair, VerifiedPublicKey},
};

const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"PRAETORE_AUTHORITY_V1\0";
const ISSUER_KEY_ID_DOMAIN: &[u8] = b"PRAETORE_ISSUER_KEY_V1\0ed25519\0";
const MAX_CAPABILITIES: usize = 256;
const MAX_AUTHORITY_CONSTRAINTS: usize = 128;
const MAX_AUTHORITY_FIELD_BYTES: usize = 1024;

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
#[serde(deny_unknown_fields)]
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
        if self.key.trim().is_empty() || self.key != self.key.trim() {
            return Err(PraetoreError::InvalidRequest(
                "authority constraint key must be a non-empty canonical name".into(),
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
#[serde(deny_unknown_fields)]
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

        if let (Some(not_before), Some(not_after)) = (not_before, not_after)
            && not_after < not_before
        {
            return Err(PraetoreError::InvalidRequest(
                "authority validity not_before cannot be after not_after".into(),
            ));
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
///
/// ```
/// use praetore_core::{AgentId, AgentKeyPair, Authority};
///
/// let agent_key = AgentKeyPair::generate();
/// let agent = agent_key.identity(AgentId::new());
/// let issuer_key = AgentKeyPair::generate();
/// let mut authority =
///     Authority::new(agent.id.clone(), "example-issuer", vec!["data:read".into()]);
/// authority.sign_for_agent(&issuer_key, &agent).expect("sign authority");
/// authority
///     .verify_subject_identity(&agent)
///     .expect("authority is bound to this agent key");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub id: AuthorityId,
    pub subject: AgentId,
    pub capabilities: Vec<String>,
    pub constraints: Vec<AuthorityConstraint>,
    pub issuer: String,
    pub validity: Validity,
    pub version: u32,
    pub subject_key_hash: Option<String>,
    pub issuer_key_id: Option<String>,
    pub signature: Option<String>,
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
    pub fn from_json(json: &str) -> Result<Self> {
        let value = parse_json_rejecting_duplicates(json).map_err(PraetoreError::InvalidRequest)?;
        let authority: Self = serde_json::from_value(value)
            .map_err(|error| PraetoreError::InvalidRequest(error.to_string()))?;
        authority.validate()?;
        Ok(authority)
    }

    pub fn new(subject: AgentId, issuer: impl Into<String>, capabilities: Vec<String>) -> Self {
        Self {
            id: AuthorityId::new(),
            subject,
            capabilities,
            constraints: Vec::new(),
            issuer: issuer.into(),
            validity: Validity::unbounded(),
            version: 1,
            subject_key_hash: None,
            issuer_key_id: None,
            signature: None,
        }
    }

    pub fn sign_for_agent(
        &mut self,
        issuer_key: &AgentKeyPair,
        agent: &AgentIdentity,
    ) -> Result<()> {
        agent.validate()?;
        if self.subject != agent.id {
            return Err(PraetoreError::AuthorityVerificationFailed);
        }
        agent.verified_public_key()?;
        self.subject_key_hash = Some(agent.key_fingerprint()?.to_hex());
        self.sign(issuer_key)
    }

    pub fn sign(&mut self, issuer_key: &AgentKeyPair) -> Result<()> {
        let mut key_hasher = Sha256::new();
        key_hasher.update(ISSUER_KEY_ID_DOMAIN);
        key_hasher.update(issuer_key.public_key().as_bytes());
        self.issuer_key_id = Some(hex::encode(key_hasher.finalize()));
        self.validate()?;
        let payload = self.canonical_signing_bytes()?;
        self.signature = Some(hex::encode(
            issuer_key.sign_domain_message(AUTHORITY_SIGNATURE_DOMAIN, &payload),
        ));
        Ok(())
    }

    pub fn verify_subject_identity(&self, agent: &AgentIdentity) -> Result<()> {
        agent
            .verified_public_key()
            .map_err(|_| PraetoreError::AuthorityVerificationFailed)?;
        let expected_key_hash = agent
            .key_fingerprint()
            .map_err(|_| PraetoreError::AuthorityVerificationFailed)?
            .to_hex();
        if self.subject != agent.id
            || self.subject_key_hash.as_deref() != Some(expected_key_hash.as_str())
        {
            return Err(PraetoreError::AuthorityVerificationFailed);
        }

        Ok(())
    }

    pub fn verify_signature(&self, issuer_key: &VerifiedPublicKey) -> Result<()> {
        self.validate()
            .map_err(|_| PraetoreError::AuthorityVerificationFailed)?;
        let signature = self
            .signature
            .as_deref()
            .ok_or(PraetoreError::AuthorityVerificationFailed)
            .and_then(|value| {
                hex::decode(value).map_err(|_| PraetoreError::AuthorityVerificationFailed)
            })?;
        let payload = self
            .canonical_signing_bytes()
            .map_err(|_| PraetoreError::AuthorityVerificationFailed)?;

        issuer_key
            .verify_domain_message(AUTHORITY_SIGNATURE_DOMAIN, &payload, &signature)
            .map_err(|_| PraetoreError::AuthorityVerificationFailed)
    }

    /// Returns the SHA-256 digest of the canonical signed authority payload.
    ///
    /// The signature itself is excluded, while every field authenticated by
    /// that signature—including subject binding, capabilities, constraints,
    /// and validity—is included.
    pub fn content_digest(&self) -> Result<String> {
        let payload = self.canonical_signing_bytes()?;
        Ok(hex::encode(Sha256::digest(payload)))
    }

    fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut capabilities: Vec<_> = self.capabilities.iter().map(String::as_str).collect();
        capabilities.sort_unstable();

        let mut constraints: Vec<_> = self.constraints.iter().collect();
        constraints.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        canonical_json(&AuthoritySigningPayload {
            canonical_version: crate::canonical::CANONICAL_VERSION,
            schema_version: 1,
            id: &self.id,
            subject: &self.subject,
            issuer: &self.issuer,
            capabilities,
            constraints,
            validity: &self.validity,
            version: self.version,
            subject_key_hash: &self.subject_key_hash,
            issuer_key_id: &self.issuer_key_id,
        })
        .map_err(|error| PraetoreError::EvidenceError(error.to_string()))
    }

    pub fn permits(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }

    /// Returns the non-nil tenant UUID in this authority, when present.
    ///
    /// This is issuer-signed routing metadata. The gateway uses it to scope
    /// replay and execution identity independently of action parameters.
    pub fn tenant_id(&self) -> Option<Uuid> {
        let mut constraints = self
            .constraints
            .iter()
            .filter(|constraint| constraint.key == "tenant_id");
        let tenant_id: Uuid = constraints.next()?.value.parse().ok()?;
        (constraints.next().is_none() && !tenant_id.is_nil()).then_some(tenant_id)
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
        if self.issuer.trim().is_empty() || self.issuer != self.issuer.trim() {
            return Err(PraetoreError::InvalidRequest(
                "authority issuer must be a non-empty canonical identifier".into(),
            ));
        }

        if self.issuer.len() > MAX_AUTHORITY_FIELD_BYTES
            || self.capabilities.len() > MAX_CAPABILITIES
            || self.constraints.len() > MAX_AUTHORITY_CONSTRAINTS
        {
            return Err(PraetoreError::InvalidRequest(
                "authority exceeds configured input limits".into(),
            ));
        }

        if self
            .subject_key_hash
            .as_deref()
            .is_some_and(|hash| hash.len() != 64 || hex::decode(hash).is_err())
        {
            return Err(PraetoreError::InvalidRequest(
                "authority subject key hash is malformed".into(),
            ));
        }
        if self
            .issuer_key_id
            .as_deref()
            .is_some_and(|key_id| key_id.len() != 64 || hex::decode(key_id).is_err())
        {
            return Err(PraetoreError::InvalidRequest(
                "authority issuer key id is malformed".into(),
            ));
        }

        if self.version == 0 {
            return Err(PraetoreError::InvalidRequest(
                "authority version must be greater than zero".into(),
            ));
        }

        let mut capabilities = HashSet::new();

        for capability in &self.capabilities {
            if capability.trim().is_empty()
                || capability != capability.trim()
                || capability.len() > MAX_AUTHORITY_FIELD_BYTES
            {
                return Err(PraetoreError::InvalidRequest(
                    "authority capability must be a non-empty canonical name".into(),
                ));
            }

            if !capabilities.insert(capability) {
                return Err(PraetoreError::InvalidRequest(format!(
                    "authority contains duplicate capability '{}'",
                    capability
                )));
            }
        }

        let mut constraint_keys = HashSet::new();

        for constraint in &self.constraints {
            constraint.validate()?;
            if constraint.key.len() > MAX_AUTHORITY_FIELD_BYTES
                || constraint.value.len() > MAX_AUTHORITY_FIELD_BYTES
            {
                return Err(PraetoreError::InvalidRequest(
                    "authority constraint exceeds maximum length".into(),
                ));
            }

            if !constraint_keys.insert(&constraint.key) {
                return Err(PraetoreError::InvalidRequest(format!(
                    "authority contains duplicate constraint key '{}'",
                    constraint.key
                )));
            }
        }

        self.validity.validate()?;

        Ok(())
    }
}

#[derive(Serialize)]
struct AuthoritySigningPayload<'a> {
    canonical_version: u8,
    schema_version: u8,
    id: &'a AuthorityId,
    subject: &'a AgentId,
    issuer: &'a str,
    capabilities: Vec<&'a str>,
    constraints: Vec<&'a AuthorityConstraint>,
    validity: &'a Validity,
    version: u32,
    subject_key_hash: &'a Option<String>,
    issuer_key_id: &'a Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeyPair;

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
    fn authority_json_parser_rejects_duplicate_fields() {
        assert!(Authority::from_json(r#"{"issuer":"one","issuer":"two"}"#).is_err());
    }

    #[test]
    fn authority_signature_matches_v1_golden_vector() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/golden/trust-chain-v1.json")).unwrap();
        let agent_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let agent_id: AgentId =
            serde_json::from_str("\"00000000-0000-0000-0000-000000000002\"").unwrap();
        let agent = agent_key.identity(agent_id);
        let mut authority =
            Authority::new(agent.id.clone(), "golden-issuer", vec!["data:read".into()])
                .with_validity(Validity {
                    not_before: Some("2026-01-01T00:00:00Z".into()),
                    not_after: Some("2027-01-01T00:00:00Z".into()),
                });
        authority.id = serde_json::from_str("\"00000000-0000-0000-0000-000000000001\"").unwrap();
        authority
            .sign_for_agent(&AgentKeyPair::from_secret_bytes(&[8; 32]), &agent)
            .unwrap();

        assert_eq!(
            String::from_utf8(authority.canonical_signing_bytes().unwrap()).unwrap(),
            golden["authority_signing_payload"].as_str().unwrap()
        );
        assert_eq!(
            authority.signature.as_deref(),
            golden["authority_signature_hex"].as_str()
        );
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
    fn validity_bounds_are_inclusive() {
        let validity = Validity {
            not_before: Some("2026-01-01T00:00:00Z".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        };
        let start = parse_timestamp("2026-01-01T00:00:00Z").unwrap();
        let end = parse_timestamp("2027-01-01T00:00:00Z").unwrap();

        assert!(validity.is_active_at(start).unwrap());
        assert!(validity.is_active_at(end).unwrap());
        assert!(
            !validity
                .is_active_at(start - time::Duration::SECOND)
                .unwrap()
        );
        assert!(!validity.is_active_at(end + time::Duration::SECOND).unwrap());
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
    fn authority_rejects_duplicate_capabilities() {
        let authority = Authority::new(
            test_agent(),
            "praetore-root",
            vec!["read:data".into(), "read:data".into()],
        );

        assert!(matches!(
            authority.validate(),
            Err(PraetoreError::InvalidRequest(_))
        ));
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
    fn authority_rejects_duplicate_constraints() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_constraint("environment", "production")
            .with_constraint("environment", "production");

        assert!(matches!(
            authority.validate(),
            Err(PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn authority_rejects_conflicting_constraints() {
        let authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()])
            .with_constraint("environment", "production")
            .with_constraint("environment", "staging");

        assert!(matches!(
            authority.validate(),
            Err(PraetoreError::InvalidRequest(_))
        ));
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

    #[test]
    fn signed_authority_verifies_with_issuer_key() {
        let issuer_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let mut authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()]);

        authority.sign(&issuer_key).unwrap();

        assert!(authority.verify_signature(&issuer_key.public_key()).is_ok());
        assert!(authority.signature.is_some());
    }

    #[test]
    fn signed_authority_rejects_tampering_and_wrong_issuer() {
        let issuer_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let other_key = AgentKeyPair::from_secret_bytes(&[8; 32]);
        let mut authority = Authority::new(test_agent(), "praetore-root", vec!["read:data".into()]);

        authority.sign(&issuer_key).unwrap();
        assert!(authority.verify_signature(&other_key.public_key()).is_err());

        authority.capabilities.push("delete:data".into());
        assert!(
            authority
                .verify_signature(&issuer_key.public_key())
                .is_err()
        );
    }

    #[test]
    fn authority_subject_key_binding_requires_matching_subject() {
        let issuer_key = AgentKeyPair::generate();
        let agent = AgentKeyPair::generate().identity(AgentId::new());
        let other_agent = AgentKeyPair::generate().identity(AgentId::new());
        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        assert!(authority.sign_for_agent(&issuer_key, &other_agent).is_err());
        authority.sign_for_agent(&issuer_key, &agent).unwrap();
        assert!(authority.verify_subject_identity(&agent).is_ok());
        assert!(authority.verify_subject_identity(&other_agent).is_err());
    }

    #[test]
    fn authority_canonical_signature_ignores_set_order() {
        let issuer_key = AgentKeyPair::from_secret_bytes(&[9; 32]);
        let subject = test_agent();
        let mut first = Authority::new(
            subject.clone(),
            "praetore-root",
            vec!["read:data".into(), "write:data".into()],
        )
        .with_constraint("region", "south")
        .with_constraint("environment", "production");
        let mut second = Authority {
            id: first.id.clone(),
            subject,
            capabilities: vec!["write:data".into(), "read:data".into()],
            constraints: vec![
                AuthorityConstraint::new("environment", "production"),
                AuthorityConstraint::new("region", "south"),
            ],
            issuer: "praetore-root".into(),
            validity: first.validity.clone(),
            version: first.version,
            subject_key_hash: None,
            issuer_key_id: None,
            signature: None,
        };

        first.sign(&issuer_key).unwrap();
        second.sign(&issuer_key).unwrap();

        assert_eq!(first.signature, second.signature);
    }
}
