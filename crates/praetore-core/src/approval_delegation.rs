//! Delegated authority to approve held actions.
//!
//! Each tenant may pin one delegation root: an Ed25519 key that signs
//! [`ApprovalDelegation`]s. A delegation names a subject key, a role
//! (`approver` or `delegator`), the exact action types it covers, a validity
//! interval and how many more levels may follow it. A `delegator` may sign
//! further delegations that never widen its own; an `approver` signs human
//! decisions and nothing else. A signed [`ApprovalRevocation`] withdraws a
//! delegation and, with it, every delegation below it.
//!
//! [`verify_approval_chain`] is the only place where a chain is checked. The
//! gateway and the offline verifier both call it, with the same signed data.
//!
//! The delegations, revocations and roots are read from one document,
//! [`DelegationConfig::from_json`]:
//!
//! ```json
//! {"schema_version":1,
//!  "roots":[{"tenant_id":"<uuid>","key_id":"tenant-a-root","public_key_hex":"<64 hex>"}],
//!  "delegations":[{...}],
//!  "revocations":[{...}]}
//! ```

use crate::{
    AgentKeyPair, VerifiedPublicKey,
    canonical::{canonicalize_json, parse_json_rejecting_duplicates},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const DELEGATION_DOMAIN: &[u8] = b"PRAETORE_APPROVAL_DELEGATION_V1\0";
const REVOCATION_DOMAIN: &[u8] = b"PRAETORE_APPROVAL_REVOCATION_V1\0";
const DELEGATION_HASH_DOMAIN: &[u8] = b"PRAETORE_APPROVAL_DELEGATION_HASH_V1\0";

/// The `schema_version` of a delegation, a revocation and the document.
pub const DELEGATION_SCHEMA_VERSION: u8 = 1;
/// Most delegations between a root and an approver.
pub const MAX_DELEGATION_CHAIN: usize = 4;
/// Most action types one delegation names.
pub const MAX_DELEGATION_ACTION_TYPES: usize = 64;
/// Largest delegation document.
pub const MAX_DELEGATION_DOCUMENT_BYTES: usize = 1_048_576;
/// Most roots, delegations or revocations in one document.
pub const MAX_DELEGATION_ENTRIES: usize = 4096;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_ACTION_TYPE_BYTES: usize = 128;

/// What the subject of a delegation may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationRole {
    /// Signs human decisions for the delegated action types.
    Approver,
    /// Signs further delegations, each within its own.
    Delegator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationScope {
    /// Exact action types. No wildcards.
    pub action_types: Vec<String>,
}

/// One signed link of a delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDelegation {
    pub schema_version: u8,
    /// Random (version 4) identifier.
    pub delegation_id: Uuid,
    pub tenant_id: Uuid,
    /// The root's key id, or the subject key id of the parent delegation.
    pub issuer_key_id: String,
    /// The hash of the parent delegation; absent when the root signs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_delegation_hash: Option<String>,
    pub subject_key_id: String,
    pub subject_public_key_hex: String,
    pub role: DelegationRole,
    pub scope: DelegationScope,
    /// RFC 3339, UTC (`Z`).
    pub not_before: String,
    /// RFC 3339, UTC (`Z`).
    pub not_after: String,
    /// How many more delegations may follow this one. Each child's is lower.
    pub max_depth: u8,
    pub signature: String,
}

#[derive(Serialize)]
struct DelegationPayload<'a> {
    schema_version: u8,
    delegation_id: Uuid,
    tenant_id: Uuid,
    issuer_key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_delegation_hash: Option<&'a str>,
    subject_key_id: &'a str,
    subject_public_key_hex: &'a str,
    role: DelegationRole,
    scope: &'a DelegationScope,
    not_before: &'a str,
    not_after: &'a str,
    max_depth: u8,
}

/// A signed withdrawal of one delegation, and of every delegation below it.
/// Signed by the delegation's issuer or by the tenant's root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRevocation {
    pub schema_version: u8,
    pub tenant_id: Uuid,
    pub delegation_hash: String,
    /// The key that signs the revocation: the delegation's issuer or the root.
    pub issuer_key_id: String,
    /// RFC 3339, UTC (`Z`).
    pub effective_at: String,
    pub signature: String,
}

#[derive(Serialize)]
struct RevocationPayload<'a> {
    schema_version: u8,
    tenant_id: Uuid,
    delegation_hash: &'a str,
    issuer_key_id: &'a str,
    effective_at: &'a str,
}

/// Why a delegation document, a chain or a delegated decision was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    #[error("delegation document is invalid")]
    InvalidDocument,
    #[error("a delegation root key or key id is shared with another tenant or another role")]
    SharedRootKey,
    #[error("a revocation is not signed by the delegation's issuer or the tenant's root")]
    InvalidRevocation,
    #[error("no delegation root for the tenant")]
    NoRoot,
    #[error("the decision does not name a known approver")]
    UnknownApprover,
    #[error("a delegation of the chain is not in the delegation document")]
    UnknownDelegation,
    #[error("the delegation chain is longer than the maximum")]
    ChainTooLong,
    #[error("a delegation is not signed by its parent")]
    WrongIssuer,
    #[error("a delegation signature does not verify")]
    InvalidSignature,
    #[error("a delegation belongs to another tenant")]
    TenantMismatch,
    #[error("a delegation names an action type its parent does not have")]
    ScopeWidened,
    #[error("a delegation is valid outside its parent's validity")]
    ValidityWidened,
    #[error("a delegation's max_depth is not lower than its parent's")]
    DepthNotDecreasing,
    #[error("an approver delegation cannot sign delegations")]
    ApproverCannotDelegate,
    #[error("a delegation grants authority to its issuer or to an earlier key of the chain")]
    Cycle,
    #[error("a delegation of the chain is revoked")]
    Revoked,
    #[error("a delegation is not valid for the whole approval window")]
    OutsideValidity,
    #[error("the last delegation of the chain is not an approver")]
    NotAnApprover,
    #[error("the decision is not signed by the chain's approver")]
    SignerMismatch,
    #[error("the chain does not cover the action type")]
    ActionNotInScope,
    #[error("the policy does not let the delegation root approve")]
    RootMayNotApprove,
    #[error("a key of the chain is the requesting agent's")]
    SelfApproval,
}

impl DelegationError {
    /// Stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidDocument => "DELEGATION_DOCUMENT_INVALID",
            Self::SharedRootKey => "DELEGATION_ROOT_SHARED",
            Self::InvalidRevocation => "DELEGATION_REVOCATION_INVALID",
            Self::NoRoot => "DELEGATION_NO_ROOT",
            Self::UnknownApprover => "DELEGATION_UNKNOWN_APPROVER",
            Self::UnknownDelegation => "DELEGATION_UNKNOWN",
            Self::ChainTooLong => "DELEGATION_CHAIN_TOO_LONG",
            Self::WrongIssuer => "DELEGATION_WRONG_ISSUER",
            Self::InvalidSignature => "DELEGATION_SIGNATURE_INVALID",
            Self::TenantMismatch => "DELEGATION_TENANT_MISMATCH",
            Self::ScopeWidened => "DELEGATION_SCOPE_WIDENED",
            Self::ValidityWidened => "DELEGATION_VALIDITY_WIDENED",
            Self::DepthNotDecreasing => "DELEGATION_DEPTH_NOT_DECREASING",
            Self::ApproverCannotDelegate => "DELEGATION_APPROVER_CANNOT_DELEGATE",
            Self::Cycle => "DELEGATION_CYCLE",
            Self::Revoked => "DELEGATION_REVOKED",
            Self::OutsideValidity => "DELEGATION_OUTSIDE_VALIDITY",
            Self::NotAnApprover => "DELEGATION_NOT_AN_APPROVER",
            Self::SignerMismatch => "DELEGATION_SIGNER_MISMATCH",
            Self::ActionNotInScope => "DELEGATION_ACTION_NOT_IN_SCOPE",
            Self::RootMayNotApprove => "DELEGATION_ROOT_MAY_NOT_APPROVE",
            Self::SelfApproval => "DELEGATION_SELF_APPROVAL",
        }
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_KEY_ID_BYTES && value.trim() == value
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A 32-byte public key as 64 lowercase hex characters.
fn parse_public_key(value: &str) -> Option<VerifiedPublicKey> {
    if value.len() != 64 || !is_lower_hex(value) {
        return None;
    }
    VerifiedPublicKey::from_bytes(&hex::decode(value).ok()?).ok()
}

/// An RFC 3339 instant written in UTC with `Z`, exactly as it formats.
fn parse_utc(value: &str) -> Option<OffsetDateTime> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    if parsed.offset() != time::UtcOffset::UTC || parsed.format(&Rfc3339).ok()? != value {
        return None;
    }
    Some(parsed)
}

fn decode_signature(value: &str) -> Option<Vec<u8>> {
    if value.len() != 128 || !is_lower_hex(value) {
        return None;
    }
    hex::decode(value).ok()
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, DelegationError> {
    let json = serde_json::to_string(value).map_err(|_| DelegationError::InvalidDocument)?;
    canonicalize_json(&json).map_err(|_| DelegationError::InvalidDocument)
}

impl ApprovalDelegation {
    fn payload(&self) -> DelegationPayload<'_> {
        DelegationPayload {
            schema_version: self.schema_version,
            delegation_id: self.delegation_id,
            tenant_id: self.tenant_id,
            issuer_key_id: &self.issuer_key_id,
            parent_delegation_hash: self.parent_delegation_hash.as_deref(),
            subject_key_id: &self.subject_key_id,
            subject_public_key_hex: &self.subject_public_key_hex,
            role: self.role,
            scope: &self.scope,
            not_before: &self.not_before,
            not_after: &self.not_after,
            max_depth: self.max_depth,
        }
    }

    /// The canonical JSON the issuer signs (every field but `signature`),
    /// after the domain `PRAETORE_APPROVAL_DELEGATION_V1\0`.
    pub fn signing_payload(&self) -> Result<Vec<u8>, DelegationError> {
        canonical(&self.payload())
    }

    /// Signs with the issuer key: the tenant's root or the parent's subject.
    pub fn sign(&mut self, issuer: &AgentKeyPair) -> Result<(), DelegationError> {
        let payload = self.signing_payload()?;
        self.signature = hex::encode(issuer.sign_domain_message(DELEGATION_DOMAIN, &payload));
        Ok(())
    }

    /// SHA-256 over `PRAETORE_APPROVAL_DELEGATION_HASH_V1\0` and the
    /// canonical JSON of the signed delegation (signature included), as 64
    /// lowercase hex characters. Chains and revocations name delegations by
    /// this hash.
    pub fn hash(&self) -> Result<String, DelegationError> {
        let mut hash = Sha256::new();
        hash.update(DELEGATION_HASH_DOMAIN);
        hash.update(canonical(self)?);
        Ok(hex::encode(hash.finalize()))
    }

    /// The format checks that do not need the parent.
    fn validate_format(&self) -> Result<(), DelegationError> {
        let action_types = &self.scope.action_types;
        let unique: BTreeSet<&String> = action_types.iter().collect();
        let window = parse_utc(&self.not_before).zip(parse_utc(&self.not_after));
        let ok = self.schema_version == DELEGATION_SCHEMA_VERSION
            && self.delegation_id.get_version_num() == 4
            && !self.tenant_id.is_nil()
            && valid_key_id(&self.issuer_key_id)
            && valid_key_id(&self.subject_key_id)
            && self
                .parent_delegation_hash
                .as_deref()
                .is_none_or(|hash| hash.len() == 64 && is_lower_hex(hash))
            && parse_public_key(&self.subject_public_key_hex).is_some()
            && !action_types.is_empty()
            && action_types.len() <= MAX_DELEGATION_ACTION_TYPES
            && unique.len() == action_types.len()
            && action_types.iter().all(|action_type| {
                !action_type.is_empty()
                    && action_type.len() <= MAX_ACTION_TYPE_BYTES
                    && action_type.trim() == action_type
                    && !action_type.contains('*')
            })
            && window.is_some_and(|(not_before, not_after)| not_before < not_after)
            && usize::from(self.max_depth) < MAX_DELEGATION_CHAIN
            && decode_signature(&self.signature).is_some();
        if ok {
            Ok(())
        } else {
            Err(DelegationError::InvalidDocument)
        }
    }

    fn verify_signature(&self, issuer: &VerifiedPublicKey) -> Result<(), DelegationError> {
        let signature =
            decode_signature(&self.signature).ok_or(DelegationError::InvalidSignature)?;
        issuer
            .verify_domain_message(DELEGATION_DOMAIN, &self.signing_payload()?, &signature)
            .map_err(|_| DelegationError::InvalidSignature)
    }

    fn subject_key(&self) -> Result<VerifiedPublicKey, DelegationError> {
        parse_public_key(&self.subject_public_key_hex).ok_or(DelegationError::InvalidDocument)
    }

    fn validity(&self) -> Result<(OffsetDateTime, OffsetDateTime), DelegationError> {
        parse_utc(&self.not_before)
            .zip(parse_utc(&self.not_after))
            .ok_or(DelegationError::InvalidDocument)
    }
}

impl ApprovalRevocation {
    fn payload(&self) -> RevocationPayload<'_> {
        RevocationPayload {
            schema_version: self.schema_version,
            tenant_id: self.tenant_id,
            delegation_hash: &self.delegation_hash,
            issuer_key_id: &self.issuer_key_id,
            effective_at: &self.effective_at,
        }
    }

    /// The canonical JSON the issuer signs (every field but `signature`),
    /// after the domain `PRAETORE_APPROVAL_REVOCATION_V1\0`.
    pub fn signing_payload(&self) -> Result<Vec<u8>, DelegationError> {
        canonical(&self.payload())
    }

    pub fn sign(&mut self, issuer: &AgentKeyPair) -> Result<(), DelegationError> {
        let payload = self.signing_payload()?;
        self.signature = hex::encode(issuer.sign_domain_message(REVOCATION_DOMAIN, &payload));
        Ok(())
    }

    fn effective_at(&self) -> Result<OffsetDateTime, DelegationError> {
        parse_utc(&self.effective_at).ok_or(DelegationError::InvalidDocument)
    }

    fn verify_signature(&self, issuer: &VerifiedPublicKey) -> Result<(), DelegationError> {
        let signature =
            decode_signature(&self.signature).ok_or(DelegationError::InvalidRevocation)?;
        issuer
            .verify_domain_message(REVOCATION_DOMAIN, &self.signing_payload()?, &signature)
            .map_err(|_| DelegationError::InvalidRevocation)
    }
}

/// The pinned delegation root of one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRoot {
    pub tenant_id: Uuid,
    pub key_id: String,
    pub public_key: VerifiedPublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationDocument {
    schema_version: u8,
    roots: Vec<RootEntry>,
    #[serde(default)]
    delegations: Vec<ApprovalDelegation>,
    #[serde(default)]
    revocations: Vec<ApprovalRevocation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootEntry {
    tenant_id: Uuid,
    key_id: String,
    public_key_hex: String,
}

/// Roots, delegations and revocations, read from one document. Every
/// revocation it holds verified when the document was read; delegations are
/// checked only as part of a chain, by [`verify_approval_chain`].
#[derive(Debug, Clone, Default)]
pub struct DelegationConfig {
    roots: BTreeMap<Uuid, DelegationRoot>,
    delegations: BTreeMap<String, ApprovalDelegation>,
    revocations: Vec<(ApprovalRevocation, OffsetDateTime)>,
}

impl DelegationConfig {
    /// Parses and checks a delegation document: duplicate keys, unknown
    /// fields and oversized documents are refused; every root has a non-nil
    /// tenant, a canonical lowercase hex key, and a key and key id no other
    /// tenant uses; every delegation is well formed and named once; every
    /// revocation is signed by the delegation's issuer or by its tenant's
    /// root.
    pub fn from_json(document: &str) -> Result<Self, DelegationError> {
        if document.len() > MAX_DELEGATION_DOCUMENT_BYTES {
            return Err(DelegationError::InvalidDocument);
        }
        let value = parse_json_rejecting_duplicates(document)
            .map_err(|_| DelegationError::InvalidDocument)?;
        let file: DelegationDocument =
            serde_json::from_value(value).map_err(|_| DelegationError::InvalidDocument)?;
        if file.schema_version != DELEGATION_SCHEMA_VERSION
            || file.roots.is_empty()
            || file.roots.len() > MAX_DELEGATION_ENTRIES
            || file.delegations.len() > MAX_DELEGATION_ENTRIES
            || file.revocations.len() > MAX_DELEGATION_ENTRIES
        {
            return Err(DelegationError::InvalidDocument);
        }
        let mut config = Self::default();
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for root in file.roots {
            let public_key =
                parse_public_key(&root.public_key_hex).ok_or(DelegationError::InvalidDocument)?;
            if root.tenant_id.is_nil() || !valid_key_id(&root.key_id) {
                return Err(DelegationError::InvalidDocument);
            }
            if config.roots.contains_key(&root.tenant_id) {
                return Err(DelegationError::InvalidDocument);
            }
            if !key_ids.insert(root.key_id.clone()) || !public_keys.insert(public_key.as_bytes()) {
                return Err(DelegationError::SharedRootKey);
            }
            config.roots.insert(
                root.tenant_id,
                DelegationRoot {
                    tenant_id: root.tenant_id,
                    key_id: root.key_id,
                    public_key,
                },
            );
        }
        for delegation in file.delegations {
            delegation.validate_format()?;
            let hash = delegation.hash()?;
            if config.delegations.insert(hash, delegation).is_some() {
                return Err(DelegationError::InvalidDocument);
            }
        }
        for revocation in file.revocations {
            let effective_at = config.check_revocation(&revocation)?;
            config.revocations.push((revocation, effective_at));
        }
        Ok(config)
    }

    /// A revocation is valid when its tenant has a root and it is signed by
    /// that root, or by the issuer of the delegation it names (the root for
    /// a first-level delegation, the parent's subject otherwise).
    fn check_revocation(
        &self,
        revocation: &ApprovalRevocation,
    ) -> Result<OffsetDateTime, DelegationError> {
        let effective_at = revocation.effective_at()?;
        if revocation.schema_version != DELEGATION_SCHEMA_VERSION
            || revocation.delegation_hash.len() != 64
            || !is_lower_hex(&revocation.delegation_hash)
            || !valid_key_id(&revocation.issuer_key_id)
        {
            return Err(DelegationError::InvalidDocument);
        }
        let root = self
            .roots
            .get(&revocation.tenant_id)
            .ok_or(DelegationError::InvalidRevocation)?;
        let signer = if revocation.issuer_key_id == root.key_id {
            // The root revokes only its own tenant's delegations.
            if self
                .delegations
                .get(&revocation.delegation_hash)
                .is_some_and(|delegation| delegation.tenant_id != revocation.tenant_id)
            {
                return Err(DelegationError::InvalidRevocation);
            }
            root.public_key.clone()
        } else {
            let delegation = self
                .delegations
                .get(&revocation.delegation_hash)
                .ok_or(DelegationError::InvalidRevocation)?;
            let parent = delegation
                .parent_delegation_hash
                .as_ref()
                .and_then(|hash| self.delegations.get(hash))
                .ok_or(DelegationError::InvalidRevocation)?;
            if delegation.tenant_id != revocation.tenant_id
                || delegation.issuer_key_id != revocation.issuer_key_id
                || parent.subject_key_id != revocation.issuer_key_id
            {
                return Err(DelegationError::InvalidRevocation);
            }
            parent
                .subject_key()
                .map_err(|_| DelegationError::InvalidRevocation)?
        };
        revocation.verify_signature(&signer)?;
        Ok(effective_at)
    }

    /// The tenant's root, if the document pins one.
    pub fn root(&self, tenant_id: Uuid) -> Option<&DelegationRoot> {
        self.roots.get(&tenant_id)
    }

    /// Every root, by tenant.
    pub fn roots(&self) -> impl Iterator<Item = &DelegationRoot> {
        self.roots.values()
    }

    fn revoked(&self, tenant_id: Uuid, hash: &str, rule: RevocationRule) -> bool {
        self.revocations.iter().any(|(revocation, effective_at)| {
            revocation.tenant_id == tenant_id
                && revocation.delegation_hash == hash
                && match rule {
                    RevocationRule::Loaded => true,
                    RevocationRule::EffectiveBy(deadline) => *effective_at <= deadline,
                }
        })
    }
}

/// Which loaded revocations count against a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationRule {
    /// Every revocation loaded (the gateway, when it records a decision or
    /// claims its dispatch).
    Loaded,
    /// Revocations effective at or before this instant: the challenge's
    /// `expires_at` (the offline verifier, which has no signed time of the
    /// decision).
    EffectiveBy(OffsetDateTime),
}

/// What [`verify_approval_chain`] needs to know about the held request.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalContext<'a> {
    pub tenant_id: Uuid,
    pub action_type: &'a str,
    /// The evidence's signed `decided_at`.
    pub window_start: OffsetDateTime,
    /// The challenge's `expires_at`.
    pub window_end: OffsetDateTime,
    /// The requesting agent's public key.
    pub agent_public_key: &'a [u8],
    /// The policy's `approval_delegation.root_may_approve`.
    pub root_may_approve: bool,
    pub revocations: RevocationRule,
}

/// A chain that verified, and the key that must have signed the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// Delegation hashes from the root to the approver; empty when the root
    /// approved.
    pub hashes: Vec<String>,
    pub approver_key_id: String,
    pub approver_key: VerifiedPublicKey,
    pub root_approved: bool,
}

struct Link<'a> {
    key_id: &'a str,
    key: VerifiedPublicKey,
    hash: Option<&'a str>,
    role: DelegationRole,
    /// `None` for the root: every action type.
    action_types: Option<&'a [String]>,
    /// `None` for the root: unbounded.
    validity: Option<(OffsetDateTime, OffsetDateTime)>,
    /// The root's is [`MAX_DELEGATION_CHAIN`].
    depth: usize,
}

/// Checks a delegation chain from the tenant's root to the key that signed
/// a decision. A child is valid only if its parent signed it, it is for the
/// same tenant, its action types are a subset of its parent's, its validity
/// lies within its parent's, its `max_depth` is lower, its parent is a
/// delegator, and its subject is neither its issuer nor any earlier key of
/// the chain. Every delegation must be unrevoked and valid for the whole
/// window, from the evidence's `decided_at` to the challenge's `expires_at`;
/// no key of the chain may be the agent's; the last delegation must be an
/// approver covering the action type and name `approver_key_id`. An empty
/// chain is the root approving itself, accepted only when the policy allows
/// it. Nothing is ever narrowed silently: any violation is an error.
pub fn verify_approval_chain(
    config: &DelegationConfig,
    chain: &[String],
    approver_key_id: &str,
    context: &ApprovalContext<'_>,
) -> Result<VerifiedChain, DelegationError> {
    let root = config
        .root(context.tenant_id)
        .ok_or(DelegationError::NoRoot)?;
    if chain.is_empty() {
        if approver_key_id != root.key_id {
            return Err(DelegationError::UnknownApprover);
        }
        if root.public_key.as_bytes().as_slice() == context.agent_public_key {
            return Err(DelegationError::SelfApproval);
        }
        if !context.root_may_approve {
            return Err(DelegationError::RootMayNotApprove);
        }
        return Ok(VerifiedChain {
            hashes: Vec::new(),
            approver_key_id: root.key_id.clone(),
            approver_key: root.public_key.clone(),
            root_approved: true,
        });
    }
    if chain.len() > MAX_DELEGATION_CHAIN {
        return Err(DelegationError::ChainTooLong);
    }
    // The root signs the first link: it may not be the agent's key either.
    if root.public_key.as_bytes().as_slice() == context.agent_public_key {
        return Err(DelegationError::SelfApproval);
    }
    let mut parent = Link {
        key_id: &root.key_id,
        key: root.public_key.clone(),
        hash: None,
        role: DelegationRole::Delegator,
        action_types: None,
        validity: None,
        depth: MAX_DELEGATION_CHAIN,
    };
    let mut seen_keys = vec![root.public_key.as_bytes()];
    let mut seen_key_ids = vec![root.key_id.as_str()];
    for hash in chain {
        let delegation = config
            .delegations
            .get(hash)
            .ok_or(DelegationError::UnknownDelegation)?;
        if delegation.tenant_id != root.tenant_id {
            return Err(DelegationError::TenantMismatch);
        }
        if parent.role != DelegationRole::Delegator {
            return Err(DelegationError::ApproverCannotDelegate);
        }
        if delegation.issuer_key_id != parent.key_id
            || delegation.parent_delegation_hash.as_deref() != parent.hash
        {
            return Err(DelegationError::WrongIssuer);
        }
        delegation.verify_signature(&parent.key)?;
        if let Some(allowed) = parent.action_types
            && !delegation
                .scope
                .action_types
                .iter()
                .all(|action_type| allowed.contains(action_type))
        {
            return Err(DelegationError::ScopeWidened);
        }
        let validity = delegation.validity()?;
        if let Some((not_before, not_after)) = parent.validity
            && (validity.0 < not_before || validity.1 > not_after)
        {
            return Err(DelegationError::ValidityWidened);
        }
        if usize::from(delegation.max_depth) >= parent.depth {
            return Err(DelegationError::DepthNotDecreasing);
        }
        let subject = delegation.subject_key()?;
        if seen_keys.contains(&subject.as_bytes())
            || seen_key_ids.contains(&delegation.subject_key_id.as_str())
        {
            return Err(DelegationError::Cycle);
        }
        if subject.as_bytes().as_slice() == context.agent_public_key {
            return Err(DelegationError::SelfApproval);
        }
        if config.revoked(delegation.tenant_id, hash, context.revocations) {
            return Err(DelegationError::Revoked);
        }
        if validity.0 > context.window_start || validity.1 < context.window_end {
            return Err(DelegationError::OutsideValidity);
        }
        seen_keys.push(subject.as_bytes());
        seen_key_ids.push(&delegation.subject_key_id);
        parent = Link {
            key_id: &delegation.subject_key_id,
            key: subject,
            hash: Some(hash),
            role: delegation.role,
            action_types: Some(&delegation.scope.action_types),
            validity: Some(validity),
            depth: usize::from(delegation.max_depth),
        };
    }
    if parent.role != DelegationRole::Approver {
        return Err(DelegationError::NotAnApprover);
    }
    if parent.key_id != approver_key_id {
        return Err(DelegationError::SignerMismatch);
    }
    if !parent
        .action_types
        .is_some_and(|action_types| action_types.iter().any(|item| item == context.action_type))
    {
        return Err(DelegationError::ActionNotInScope);
    }
    Ok(VerifiedChain {
        hashes: chain.to_vec(),
        approver_key_id: parent.key_id.to_owned(),
        approver_key: parent.key,
        root_approved: false,
    })
}
