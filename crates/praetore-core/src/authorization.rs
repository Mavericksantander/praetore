use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::{
    Result,
    action::{Action, MissionAction, RequestAction, UnclassifiedAction},
    authority::Authority,
    canonical::{MAX_JSON_VALUE_BYTES, canonical_json, decode_lower_hex, validate_json_value},
    decision::Decision,
    evidence::Evidence,
    identity::{AgentIdentity, AgentKeyPair, REQUEST_INTENT_DOMAIN},
    policy::Policy,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const REQUEST_INTENT_V2_DOMAIN: &[u8] = b"PRAETORE_INTENT_V2\0";
const MAX_INTENT_BYTES: usize = MAX_JSON_VALUE_BYTES - 8192;

const MAX_CONTEXT_KEYS: usize = 128;
const MAX_CONTEXT_KEY_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize)]
/// An agent's request to authorize one mission action under one delegated
/// authority.
///
/// Strict and HighAssurance engines require the agent to sign the intent with
/// the key bound to the authority's subject. See the runnable
/// `quickstart` example for issuance, signing, evaluation, and verification.
///
/// `action` is a [`MissionAction`], which only
/// [`Policy::classify`] produces, so a request can never carry a safety
/// action (G7). It serializes exactly like an [`Action`]; the JSON form is
/// read back with [`Self::from_json`], which classifies the action against
/// a policy first.
///
/// A [`SafetyAction`](crate::SafetyAction) does not fit:
///
/// ```compile_fail,E0308
/// use praetore_core::{
///     Action, ActionClass, AgentId, AgentKeyPair, Authority, AuthorizationRequest,
///     ClassifiedAction, Policy,
/// };
/// use serde_json::json;
///
/// let policy = Policy::new_v2("p", 1, vec![]).with_action_class("safety:halt", ActionClass::Safety);
/// let ClassifiedAction::Safety(halt) =
///     policy.classify(Action::new("safety:halt", None, json!({})).unwrap()).unwrap()
/// else {
///     unreachable!()
/// };
/// let agent = AgentKeyPair::from_secret_bytes(&[7; 32]).identity(AgentId::new());
/// let authority = Authority::new(agent.id.clone(), "issuer", vec![]);
/// // E0308: expected `MissionAction`, found `SafetyAction`.
/// let _ = AuthorizationRequest::new(agent, authority, halt);
/// ```
pub struct AuthorizationRequest<A = MissionAction> {
    pub request_id: Uuid,
    pub agent: AgentIdentity,
    pub authority: Authority,
    pub action: A,
    pub trace_id: Option<String>,
    pub context: BTreeMap<String, Value>,
    pub agent_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_v2: Option<AuthorizationIntentV2>,
}

/// The JSON form of an [`AuthorizationRequest`] before its action is
/// classified. Private: the only way out is [`AuthorizationRequest::from_json`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRequestDocument {
    request_id: Uuid,
    agent: AgentIdentity,
    authority: Authority,
    action: Action,
    trace_id: Option<String>,
    context: BTreeMap<String, Value>,
    agent_signature: Option<String>,
    #[serde(default)]
    intent_v2: Option<AuthorizationIntentV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationIntentV2 {
    pub audience: String,
    pub issued_at: String,
    pub expires_at: String,
    pub policy_digest: String,
}

/// A request for an [`UnclassifiedAction`]. The engine only refuses it, with
/// a signed DENY ([`AuthorizationEngine::refuse_unclassified`](crate::engine::AuthorizationEngine::refuse_unclassified)).
pub type UnclassifiedRequest = AuthorizationRequest<UnclassifiedAction>;

/// A parsed request, by the class of its action.
#[derive(Debug, Clone)]
pub enum ClassifiedRequest {
    Mission(AuthorizationRequest),
    Unclassified(UnclassifiedRequest),
}

fn parse_document(json: &str) -> Result<AuthorizationRequestDocument> {
    if json.len() > MAX_JSON_VALUE_BYTES {
        return Err(crate::PraetoreError::InvalidRequest(
            "authorization request exceeds maximum size".into(),
        ));
    }
    let value = crate::canonical::parse_json_rejecting_duplicates(json)
        .map_err(crate::PraetoreError::InvalidRequest)?;
    serde_json::from_value(value)
        .map_err(|error| crate::PraetoreError::InvalidRequest(error.to_string()))
}

impl AuthorizationRequestDocument {
    fn into_request<A: RequestAction>(self, action: A) -> Result<AuthorizationRequest<A>> {
        let request = AuthorizationRequest {
            request_id: self.request_id,
            agent: self.agent,
            authority: self.authority,
            action,
            trace_id: self.trace_id,
            context: self.context,
            agent_signature: self.agent_signature,
            intent_v2: self.intent_v2,
        };
        request.validate()?;
        Ok(request)
    }
}

impl AuthorizationRequest<UnclassifiedAction> {
    /// Builds a request for an unclassified action; the engine will only
    /// refuse it.
    pub fn new_unclassified(
        agent: AgentIdentity,
        authority: Authority,
        action: UnclassifiedAction,
    ) -> Result<Self> {
        Self::build(agent, authority, action)
    }
}

impl AuthorizationRequest {
    pub fn new(agent: AgentIdentity, authority: Authority, action: MissionAction) -> Result<Self> {
        Self::build(agent, authority, action)
    }

    /// Parses a serialized request and classifies its action against
    /// `policy` before anything else looks at it.
    ///
    /// A `Safety` action returns
    /// [`PraetoreError::SafetyActionNotGoverned`](crate::PraetoreError::SafetyActionNotGoverned)
    /// and an undeclared one
    /// [`PraetoreError::UnclassifiedAction`](crate::PraetoreError::UnclassifiedAction);
    /// neither is validated further, evaluated, signed or recorded. Malformed
    /// JSON and invalid fields return `InvalidRequest`. See
    /// [`Self::classify_json`] to refuse undeclared actions with a receipt.
    pub fn from_json(json: &str, policy: &Policy) -> Result<Self> {
        let document = parse_document(json)?;
        let action = policy.classify(document.action.clone())?.into_mission()?;
        document.into_request(action)
    }

    /// Like [`Self::from_json`], but an action whose type the policy does not
    /// declare yields [`ClassifiedRequest::Unclassified`] instead of an error,
    /// so the caller can have the engine refuse it with a signed DENY. A
    /// `Safety` action still returns `SafetyActionNotGoverned`.
    pub fn classify_json(json: &str, policy: &Policy) -> Result<ClassifiedRequest> {
        let document = parse_document(json)?;
        match policy.classify(document.action.clone()) {
            Ok(classified) => Ok(ClassifiedRequest::Mission(
                document.into_request(classified.into_mission()?)?,
            )),
            Err(crate::PraetoreError::UnclassifiedAction { .. }) => {
                let action = policy.unclassified(document.action.clone())?;
                Ok(ClassifiedRequest::Unclassified(
                    document.into_request(action)?,
                ))
            }
            Err(error) => Err(error),
        }
    }
}

impl<A: RequestAction> AuthorizationRequest<A> {
    fn build(agent: AgentIdentity, authority: Authority, action: A) -> Result<Self> {
        agent.validate()?;

        if agent.id != authority.subject {
            return Err(crate::PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        authority.validate()?;
        action.action().validate()?;

        Ok(Self {
            request_id: Uuid::new_v4(),
            agent,
            authority,
            action,
            trace_id: None,
            context: BTreeMap::new(),
            agent_signature: None,
            intent_v2: None,
        })
    }

    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }

    pub fn sign_intent(&mut self, agent_key: &AgentKeyPair) -> Result<()> {
        self.intent_v2 = None;
        self.validate()?;

        let verified_key = self.agent.verified_public_key()?;
        if verified_key != agent_key.public_key() {
            return Err(crate::PraetoreError::IdentityVerificationFailed);
        }

        let payload = self.canonical_intent_bytes()?;
        self.agent_signature = Some(hex::encode(
            agent_key.sign_domain_message(REQUEST_INTENT_DOMAIN, &payload),
        ));
        Ok(())
    }

    pub fn sign_intent_v2(
        &mut self,
        agent_key: &AgentKeyPair,
        audience: impl Into<String>,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        policy_digest: impl Into<String>,
    ) -> Result<()> {
        self.agent_signature = None;
        self.intent_v2 = Some(AuthorizationIntentV2 {
            audience: audience.into(),
            issued_at: canonical_timestamp(issued_at)?,
            expires_at: canonical_timestamp(expires_at)?,
            policy_digest: policy_digest.into(),
        });
        self.validate()?;

        let verified_key = self.agent.verified_public_key()?;
        if verified_key != agent_key.public_key() {
            return Err(crate::PraetoreError::IdentityVerificationFailed);
        }

        let payload = self.canonical_intent_bytes()?;
        self.agent_signature = Some(hex::encode(
            agent_key.sign_domain_message(REQUEST_INTENT_V2_DOMAIN, &payload),
        ));
        Ok(())
    }

    pub fn verify_intent_signature(&self) -> Result<()> {
        self.validate()?;
        let signature = self
            .agent_signature
            .as_deref()
            .ok_or(crate::PraetoreError::IdentityVerificationFailed)
            .and_then(|value| {
                decode_lower_hex(value).ok_or(crate::PraetoreError::IdentityVerificationFailed)
            })?;
        let payload = self.canonical_intent_bytes()?;

        self.agent.verified_public_key()?.verify_domain_message(
            if self.intent_v2.is_some() {
                REQUEST_INTENT_V2_DOMAIN
            } else {
                REQUEST_INTENT_DOMAIN
            },
            &payload,
            &signature,
        )
    }

    fn canonical_intent_bytes(&self) -> Result<Vec<u8>> {
        let payload = if let Some(intent_v2) = &self.intent_v2 {
            canonical_json(&RequestIntentV2Payload {
                canonical_version: crate::canonical::CANONICAL_VERSION,
                schema_version: 2,
                request_id: self.request_id,
                agent: &self.agent,
                authority: &self.authority,
                action: RequestAction::action(&self.action),
                trace_id: &self.trace_id,
                context: &self.context,
                intent_v2,
            })
        } else {
            canonical_json(&RequestIntentPayload {
                canonical_version: crate::canonical::CANONICAL_VERSION,
                schema_version: 1,
                request_id: self.request_id,
                agent: &self.agent,
                authority: &self.authority,
                action: RequestAction::action(&self.action),
                trace_id: &self.trace_id,
                context: &self.context,
            })
        }
        .map_err(|error| crate::PraetoreError::InvalidRequest(error.to_string()))?;
        if payload.len() > MAX_INTENT_BYTES {
            return Err(crate::PraetoreError::InvalidRequest(
                "signed authorization intent exceeds maximum size".into(),
            ));
        }
        Ok(payload)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.agent.validate()?;
        self.authority.validate()?;
        RequestAction::action(&self.action).validate()?;

        if self.agent.id != self.authority.subject {
            return Err(crate::PraetoreError::InvalidRequest(
                "authority subject does not match agent identity".into(),
            ));
        }

        if self
            .trace_id
            .as_deref()
            .is_some_and(|trace_id| trace_id.trim().is_empty())
        {
            return Err(crate::PraetoreError::InvalidRequest(
                "trace id cannot be empty".into(),
            ));
        }

        if let Some(intent_v2) = &self.intent_v2 {
            validate_intent_v2(intent_v2)?;
        }
        if self
            .trace_id
            .as_deref()
            .is_some_and(|trace_id| trace_id.len() > 1024)
        {
            return Err(crate::PraetoreError::InvalidRequest(
                "trace id exceeds maximum length".into(),
            ));
        }

        if self.context.keys().any(|key| key.trim().is_empty()) {
            return Err(crate::PraetoreError::InvalidRequest(
                "request context keys cannot be empty".into(),
            ));
        }

        if self.context.len() > MAX_CONTEXT_KEYS {
            return Err(crate::PraetoreError::InvalidRequest(
                "request context has too many keys".into(),
            ));
        }

        let mut context_bytes = 0usize;
        for (key, value) in &self.context {
            if key.len() > MAX_CONTEXT_KEY_BYTES || key != key.trim() {
                return Err(crate::PraetoreError::InvalidRequest(
                    "request context key is too long or not canonical".into(),
                ));
            }
            context_bytes += key.len();
            context_bytes += validate_json_value(value)
                .map_err(|error| crate::PraetoreError::InvalidRequest(error.to_string()))?;
            if context_bytes > MAX_JSON_VALUE_BYTES {
                return Err(crate::PraetoreError::InvalidRequest(
                    "request context exceeds maximum size".into(),
                ));
            }
        }

        Ok(())
    }

    pub fn attest(self, decision: Decision) -> Result<Evidence> {
        self.validate()?;

        Evidence::new_with_context(
            self.request_id,
            self.agent,
            self.authority,
            RequestAction::action(&self.action).clone(),
            decision,
            self.trace_id,
            self.context,
        )?
        .with_agent_signature(self.agent_signature)?
        .with_intent_v2(self.intent_v2)
    }
}

fn canonical_timestamp(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| crate::PraetoreError::InvalidRequest("invalid intent timestamp".into()))
}

pub(crate) fn validate_intent_v2(intent: &AuthorizationIntentV2) -> Result<()> {
    if intent.audience.trim().is_empty()
        || intent.audience != intent.audience.trim()
        || intent.audience.len() > 256
    {
        return Err(crate::PraetoreError::InvalidRequest(
            "intent audience is invalid".into(),
        ));
    }
    let issued_at = OffsetDateTime::parse(&intent.issued_at, &Rfc3339)
        .map_err(|_| crate::PraetoreError::InvalidRequest("intent issued_at is invalid".into()))?;
    let expires_at = OffsetDateTime::parse(&intent.expires_at, &Rfc3339)
        .map_err(|_| crate::PraetoreError::InvalidRequest("intent expires_at is invalid".into()))?;
    if canonical_timestamp(issued_at)? != intent.issued_at
        || canonical_timestamp(expires_at)? != intent.expires_at
        || expires_at < issued_at
    {
        return Err(crate::PraetoreError::InvalidRequest(
            "intent timestamps are not canonical or are inverted".into(),
        ));
    }
    let digest_bytes = hex::decode(&intent.policy_digest).map_err(|_| {
        crate::PraetoreError::InvalidRequest("intent policy digest is invalid".into())
    })?;
    if intent.policy_digest.len() != 64 || hex::encode(digest_bytes) != intent.policy_digest {
        return Err(crate::PraetoreError::InvalidRequest(
            "intent policy digest is invalid".into(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct RequestIntentPayload<'a> {
    canonical_version: u8,
    schema_version: u8,
    request_id: Uuid,
    agent: &'a AgentIdentity,
    authority: &'a Authority,
    action: &'a Action,
    trace_id: &'a Option<String>,
    context: &'a BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct RequestIntentV2Payload<'a> {
    canonical_version: u8,
    schema_version: u8,
    request_id: Uuid,
    agent: &'a AgentIdentity,
    authority: &'a Authority,
    action: &'a Action,
    trace_id: &'a Option<String>,
    context: &'a BTreeMap<String, Value>,
    intent_v2: &'a AuthorizationIntentV2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::Action,
        authority::Authority,
        decision::DecisionOutcome,
        identity::{AgentId, AgentIdentity, AgentKeyPair},
    };
    use serde_json::json;
    use time::Duration;

    fn test_agent() -> AgentIdentity {
        AgentIdentity::new(AgentId::new(), b"test-public-key".to_vec(), "ed25519").unwrap()
    }

    fn test_action() -> Action {
        Action::new(
            "read_data",
            Some("database".into()),
            json!({"table": "users"}),
        )
        .unwrap()
    }

    fn test_policy() -> Policy {
        Policy::new_v2("p", 1, vec![])
            .with_mission_actions(["read_data"])
            .with_action_class("safety:halt", crate::policy::ActionClass::Safety)
    }

    fn mission(action: Action) -> MissionAction {
        test_policy()
            .classify(action)
            .unwrap()
            .into_mission()
            .unwrap()
    }

    fn test_request() -> AuthorizationRequest {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        AuthorizationRequest::new(agent, authority, mission(test_action())).unwrap()
    }

    #[test]
    fn creates_authorization_request() {
        let request = test_request();

        assert!(!request.request_id.is_nil());
        assert_eq!(request.agent.id, request.authority.subject);
    }

    #[test]
    fn creates_unique_request_ids() {
        let first = test_request();
        let second = test_request();

        assert_ne!(first.request_id, second.request_id);
    }

    #[test]
    fn rejects_mismatched_authority() {
        let agent = test_agent();
        let other_agent = test_agent();

        let authority = Authority::new(
            other_agent.id.clone(),
            "praetore-root",
            vec!["read:data".into()],
        );

        let result = AuthorizationRequest::new(agent, authority, mission(test_action()));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_invalid_authority() {
        let agent = test_agent();

        let mut authority =
            Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        authority.issuer = String::new();

        let result = AuthorizationRequest::new(agent, authority, mission(test_action()));

        assert!(matches!(
            result,
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_invalid_action() {
        let agent = test_agent();
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);

        let action = Action {
            action_type: "   ".into(),
            capability: None,
            target: None,
            parameters: json!({}),
        };

        let _ = (agent, authority);
        // An invalid action never becomes a MissionAction.
        assert!(matches!(
            test_policy().classify(action),
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn trace_id_can_be_attached() {
        let request = test_request().with_trace_id("trace-001");

        assert_eq!(request.trace_id.as_deref(), Some("trace-001"));
    }

    #[test]
    fn trace_id_is_optional() {
        let request = test_request();

        assert!(request.trace_id.is_none());
    }

    #[test]
    fn attest_creates_verifiable_evidence() {
        let request = test_request();

        let evidence = request
            .attest(Decision::allow(
                "policy permitted action",
                crate::DecidedBy::rule("test-rule"),
            ))
            .unwrap();

        assert_eq!(evidence.decision.outcome, DecisionOutcome::Allow);
        assert!(evidence.verify());
    }

    #[test]
    fn attest_preserves_request_id() {
        let request = test_request();
        let request_id = request.request_id;

        let evidence = request
            .attest(Decision::deny(
                "policy rejected action",
                crate::DecidedBy::rule("test-rule"),
            ))
            .unwrap();

        assert_eq!(evidence.request_id, request_id);
    }

    #[test]
    fn attest_preserves_trace_id() {
        let request = test_request().with_trace_id("trace-001");

        let evidence = request
            .attest(Decision::allow(
                "policy permitted action",
                crate::DecidedBy::rule("test-rule"),
            ))
            .unwrap();

        assert_eq!(evidence.trace_id.as_deref(), Some("trace-001"));
        assert!(evidence.verify());
    }

    #[test]
    fn attest_rejects_tampered_subject_binding() {
        let mut request = test_request();
        request.agent.id = AgentId::new();

        assert!(matches!(
            request.attest(Decision::allow(
                "policy permitted action",
                crate::DecidedBy::rule("test-rule")
            )),
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn attest_rejects_empty_trace_id() {
        let mut request = test_request();
        request.trace_id = Some("   ".into());

        assert!(matches!(
            request.attest(Decision::allow(
                "policy permitted action",
                crate::DecidedBy::rule("test-rule")
            )),
            Err(crate::PraetoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn signed_request_intent_verifies_and_binds_context() {
        let keypair = AgentKeyPair::generate();
        let agent = keypair.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut request = AuthorizationRequest::new(agent, authority, mission(test_action()))
            .unwrap()
            .with_context("region", serde_json::json!("santiago"));

        request.sign_intent(&keypair).unwrap();
        assert!(request.verify_intent_signature().is_ok());

        request
            .context
            .insert("region".into(), serde_json::json!("north"));
        assert!(request.verify_intent_signature().is_err());
    }

    #[test]
    fn request_rejects_signature_from_other_agent_key() {
        let keypair = AgentKeyPair::generate();
        let other_keypair = AgentKeyPair::generate();
        let agent = keypair.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut request =
            AuthorizationRequest::new(agent, authority, mission(test_action())).unwrap();

        assert!(matches!(
            request.sign_intent(&other_keypair),
            Err(crate::PraetoreError::IdentityVerificationFailed)
        ));
    }

    #[test]
    fn v2_intent_signature_binds_audience_expiry_and_policy_digest() {
        let keypair = AgentKeyPair::from_secret_bytes(&[41; 32]);
        let agent = keypair.identity(AgentId::new());
        let authority = Authority::new(agent.id.clone(), "praetore-root", vec!["read:data".into()]);
        let mut request =
            AuthorizationRequest::new(agent, authority, mission(test_action())).unwrap();
        let issued_at = OffsetDateTime::parse("2026-06-01T12:00:00Z", &Rfc3339).unwrap();
        request
            .sign_intent_v2(
                &keypair,
                "test-gateway",
                issued_at,
                issued_at + Duration::minutes(1),
                "a".repeat(64),
            )
            .unwrap();
        assert!(request.verify_intent_signature().is_ok());

        let mut changed_audience = request.clone();
        changed_audience.intent_v2.as_mut().unwrap().audience = "other-gateway".into();
        assert!(changed_audience.verify_intent_signature().is_err());

        let mut changed_expiry = request.clone();
        changed_expiry.intent_v2.as_mut().unwrap().expires_at = "2026-06-01T12:02:00Z".into();
        assert!(changed_expiry.verify_intent_signature().is_err());

        let mut changed_policy = request.clone();
        changed_policy.intent_v2.as_mut().unwrap().policy_digest = "b".repeat(64);
        assert!(changed_policy.verify_intent_signature().is_err());
    }

    #[test]
    fn request_import_rejects_duplicate_unknown_and_oversized_json() {
        let policy = test_policy();
        assert!(
            AuthorizationRequest::from_json(
                r#"{"request_id":"00000000-0000-0000-0000-000000000001","request_id":"00000000-0000-0000-0000-000000000002"}"#,
                &policy
            )
            .is_err()
        );
        let mut document = serde_json::to_value(test_request()).unwrap();
        assert!(AuthorizationRequest::from_json(&document.to_string(), &policy).is_ok());
        document["unexpected"] = json!(true);
        assert!(AuthorizationRequest::from_json(&document.to_string(), &policy).is_err());

        let oversized = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_JSON_VALUE_BYTES));
        assert!(AuthorizationRequest::from_json(&oversized, &policy).is_err());
    }

    #[test]
    fn request_import_classifies_the_action_before_anything_else() {
        let policy = test_policy();
        let mut document = serde_json::to_value(test_request()).unwrap();
        document["action"]["action_type"] = json!("safety:halt");
        assert!(matches!(
            AuthorizationRequest::from_json(&document.to_string(), &policy),
            Err(crate::PraetoreError::SafetyActionNotGoverned { action_type }) if action_type == "safety:halt"
        ));
        document["action"]["action_type"] = json!("fs:delete");
        assert!(matches!(
            AuthorizationRequest::from_json(&document.to_string(), &policy),
            Err(crate::PraetoreError::UnclassifiedAction { action_type }) if action_type == "fs:delete"
        ));
    }

    #[test]
    fn mission_action_serializes_exactly_like_its_action() {
        let action = test_action();
        assert_eq!(
            serde_json::to_string(&mission(action.clone())).unwrap(),
            serde_json::to_string(&action).unwrap()
        );
    }

    #[test]
    fn request_intent_matches_v1_golden_vector() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../../../docs/golden/trust-chain-v1.json")).unwrap();
        let agent_key = AgentKeyPair::from_secret_bytes(&[7; 32]);
        let agent_id: AgentId =
            serde_json::from_str("\"00000000-0000-0000-0000-000000000002\"").unwrap();
        let agent = agent_key.identity(agent_id);
        let mut authority =
            Authority::new(agent.id.clone(), "golden-issuer", vec!["data:read".into()])
                .with_validity(crate::authority::Validity {
                    not_before: Some("2026-01-01T00:00:00Z".into()),
                    not_after: Some("2027-01-01T00:00:00Z".into()),
                });
        authority.id = serde_json::from_str("\"00000000-0000-0000-0000-000000000001\"").unwrap();
        authority
            .sign_for_agent(&AgentKeyPair::from_secret_bytes(&[8; 32]), &agent)
            .unwrap();
        let action = Action::new("read_data", Some("dataset".into()), json!({}))
            .unwrap()
            .with_capability("data:read");
        let mut request = AuthorizationRequest::new(agent, authority, mission(action)).unwrap();
        request.request_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();

        assert_eq!(
            String::from_utf8(request.canonical_intent_bytes().unwrap()).unwrap(),
            golden["intent_signing_payload"].as_str().unwrap()
        );
        request.sign_intent(&agent_key).unwrap();
        assert_eq!(
            request.agent_signature.as_deref(),
            golden["intent_signature_hex"].as_str()
        );
    }
}
