//! D2: the approvals inbox.
//!
//! Which requests wait for a person, said in plain words: who, what, on what,
//! and until when. The browser never receives the journal keys: each pending
//! request gets an opaque reference that only this process can resolve.

use crate::historia::readable_time;
use praetore_core::Evidence;
use praetore_gateway::{ApprovalChallenge, ExecutionKey, action_digest};
use std::{collections::HashMap, sync::Mutex};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

/// How many pending requests one inbox read returns, newest first.
pub const INBOX_LIMIT: u32 = 200;
/// Opaque references kept in memory before the table is reset.
const MAX_REFERENCES: usize = 4096;
const REFERENCE_ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz23456789_";
const REFERENCE_LEN: usize = 20;

/// What a pending request still needs from the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// Nobody has decided yet: approve or reject.
    AwaitingApproval,
    /// Approved, and the single execution has not happened yet.
    ApprovedPendingExecution,
}

impl PendingKind {
    pub fn phrase(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "pendiente de aprobación",
            Self::ApprovedPendingExecution => "aprobado, pendiente de ejecución",
        }
    }
}

/// One journal row that waits for the operator, reduced to what the console
/// may say plus what it needs to check the gateway challenge before signing.
#[derive(Debug, Clone)]
pub struct PendingFacts {
    pub created_at: OffsetDateTime,
    pub key: ExecutionKey,
    pub kind: PendingKind,
    pub wanted: String,
    pub target: Option<String>,
    /// Digest of the action read from the signed journal evidence. The
    /// challenge the gateway hands back must commit to this same digest.
    pub action_digest: String,
    /// The challenge the gateway must hand back, rebuilt from the evidence
    /// exactly as the gateway builds it.
    pub expected: ApprovalChallenge,
    pub expires_at: OffsetDateTime,
}

/// Journal columns the inbox reads. Evidence JSON is consumed here.
pub struct PendingColumns {
    pub created_at: OffsetDateTime,
    pub agent_id: Uuid,
    pub request_id: Uuid,
    pub kind: PendingKind,
    pub evidence_json: String,
}

/// Fails closed on any receipt that does not verify, belongs to another
/// tenant or key, or has no approval window.
pub fn pending_from_columns(tenant_id: Uuid, columns: PendingColumns) -> Result<PendingFacts, ()> {
    let evidence = Evidence::from_json(&columns.evidence_json).map_err(|_| ())?;
    if !evidence.verify_integrity() {
        return Err(());
    }
    let digest = action_digest(&evidence.action).map_err(|_| ())?;
    let challenge = ApprovalChallenge::from_evidence(&evidence, &digest).map_err(|_| ())?;
    if challenge.tenant_id != tenant_id
        || challenge.agent_id != columns.agent_id
        || challenge.request_id != columns.request_id
    {
        return Err(());
    }
    let expires_at = OffsetDateTime::parse(&challenge.expires_at, &Rfc3339).map_err(|_| ())?;
    let challenge = challenge.clone();
    let target = evidence.action.target.filter(|target| !target.is_empty());
    Ok(PendingFacts {
        created_at: columns.created_at,
        key: ExecutionKey {
            tenant_id,
            agent_id: columns.agent_id,
            request_id: columns.request_id,
        },
        kind: columns.kind,
        wanted: evidence.action.action_type,
        target,
        action_digest: digest,
        expected: challenge,
        expires_at,
    })
}

/// Expiry with seconds: windows can be short.
pub fn readable_deadline(moment: OffsetDateTime) -> String {
    let moment = moment.to_offset(time::UtcOffset::UTC);
    let minutes = readable_time(moment);
    // "12 de noviembre de 2026, 15:04 UTC" -> "..., 15:04:09 UTC"
    match minutes.strip_suffix(" UTC") {
        Some(base) => format!("{base}:{:02} UTC", moment.second()),
        None => minutes,
    }
}

/// Plain words for the time left, from the console's clock. Informational:
/// the gateway decides with its trusted clock.
pub fn time_left(expires_at: OffsetDateTime, now: OffsetDateTime) -> String {
    let left = expires_at - now;
    let seconds = left.whole_seconds();
    if seconds <= 0 {
        "la ventana ya cerró".to_owned()
    } else if seconds < 60 {
        "quedan menos de un minuto".to_owned()
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        if minutes == 1 {
            "queda 1 minuto".to_owned()
        } else {
            format!("quedan {minutes} minutos")
        }
    } else {
        let hours = seconds / 3600;
        if hours == 1 {
            "queda más de 1 hora".to_owned()
        } else {
            format!("quedan más de {hours} horas")
        }
    }
}

/// What a reference resolves to. Only this process knows the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRef {
    pub key: ExecutionKey,
    pub action_digest: String,
    pub expected: ApprovalChallenge,
}

impl From<&PendingFacts> for PendingRef {
    fn from(facts: &PendingFacts) -> Self {
        Self {
            key: facts.key,
            action_digest: facts.action_digest.clone(),
            expected: facts.expected.clone(),
        }
    }
}

/// Opaque references for pending requests. A reference is random, stable
/// for the same request while this process runs, and meaningless after a
/// restart (an old page then gets "ya no está").
#[derive(Default)]
pub struct References {
    inner: Mutex<ReferenceTable>,
}

#[derive(Default)]
struct ReferenceTable {
    by_reference: HashMap<String, PendingRef>,
    by_key: HashMap<(Uuid, Uuid), String>,
}

impl References {
    pub fn reference_for(&self, facts: &PendingFacts) -> Option<String> {
        let mut table = self.inner.lock().ok()?;
        let key = (facts.key.agent_id, facts.key.request_id);
        if let Some(existing) = table.by_key.get(&key).cloned()
            && let Some(known) = table.by_reference.get(&existing)
        {
            if known.action_digest == facts.action_digest
                && known.key == facts.key
                && known.expected == facts.expected
            {
                return Some(existing);
            }
            // Same journal key, different action: never reuse the reference.
            table.by_reference.remove(&existing);
            table.by_key.remove(&key);
        }
        if table.by_reference.len() >= MAX_REFERENCES {
            table.by_reference.clear();
            table.by_key.clear();
        }
        let reference = loop {
            let candidate = new_reference()?;
            if !table.by_reference.contains_key(&candidate) {
                break candidate;
            }
        };
        table
            .by_reference
            .insert(reference.clone(), PendingRef::from(facts));
        table.by_key.insert(key, reference.clone());
        Some(reference)
    }

    pub fn resolve(&self, reference: &str) -> Option<PendingRef> {
        if !valid_reference(reference) {
            return None;
        }
        self.inner.lock().ok()?.by_reference.get(reference).cloned()
    }
}

pub fn valid_reference(reference: &str) -> bool {
    reference.len() == REFERENCE_LEN
        && reference
            .bytes()
            .all(|byte| REFERENCE_ALPHABET.contains(&byte))
}

/// A random code from the reference alphabet: not hex, not a UUID.
pub fn random_code() -> Option<String> {
    new_reference()
}

fn new_reference() -> Option<String> {
    let bytes = crate::sesion::random_bytes().ok()?;
    Some(
        bytes[..REFERENCE_LEN]
            .iter()
            .map(|byte| char::from(REFERENCE_ALPHABET[usize::from(byte & 31)]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn facts(request: u128, digest: &str) -> PendingFacts {
        PendingFacts {
            created_at: datetime!(2026-11-12 10:00 UTC),
            key: ExecutionKey {
                tenant_id: Uuid::from_u128(1),
                agent_id: Uuid::from_u128(2),
                request_id: Uuid::from_u128(request),
            },
            kind: PendingKind::AwaitingApproval,
            wanted: "borrar_archivo".into(),
            target: Some("informe".into()),
            action_digest: digest.into(),
            expected: ApprovalChallenge {
                schema_version: 1,
                tenant_id: Uuid::from_u128(1),
                agent_id: Uuid::from_u128(2),
                request_id: Uuid::from_u128(request),
                evidence_id: Uuid::from_u128(request),
                evidence_hash: String::new(),
                action_digest: digest.into(),
                policy_digest: String::new(),
                expires_at: String::new(),
            },
            expires_at: datetime!(2026-11-12 10:05:09 UTC),
        }
    }

    #[test]
    fn references_are_opaque_stable_and_bound_to_the_action() {
        let references = References::default();
        let first = references.reference_for(&facts(3, "aa")).unwrap();
        assert!(valid_reference(&first));
        assert!(Uuid::parse_str(&first).is_err());
        assert!(!first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(references.reference_for(&facts(3, "aa")).unwrap(), first);
        let other = references.reference_for(&facts(4, "aa")).unwrap();
        assert_ne!(other, first);
        let resolved = references.resolve(&first).unwrap();
        assert_eq!(resolved.key.request_id, Uuid::from_u128(3));
        assert_eq!(resolved.action_digest, "aa");

        // A different action under the same key gets a new reference and the
        // old one stops resolving.
        let changed = references.reference_for(&facts(3, "bb")).unwrap();
        assert_ne!(changed, first);
        assert!(references.resolve(&first).is_none());
        assert_eq!(references.resolve(&changed).unwrap().action_digest, "bb");

        assert!(references.resolve("no-es-una-referencia").is_none());
        assert!(references.resolve(&"a".repeat(REFERENCE_LEN)).is_none());
    }

    #[test]
    fn deadlines_are_words_with_seconds() {
        assert_eq!(
            readable_deadline(datetime!(2026-11-12 10:05:09 UTC)),
            "12 de noviembre de 2026, 10:05:09 UTC"
        );
        let now = datetime!(2026-11-12 10:00 UTC);
        assert_eq!(
            time_left(datetime!(2026-11-12 10:00:30 UTC), now),
            "quedan menos de un minuto"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 10:05:09 UTC), now),
            "quedan 5 minutos"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 13:00 UTC), now),
            "quedan más de 3 horas"
        );
        assert_eq!(
            time_left(datetime!(2026-11-12 09:00 UTC), now),
            "la ventana ya cerró"
        );
    }
}
