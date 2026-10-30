//! Freshness providers for the gateway service.
//!
//! [`FileFreshnessProvider`] is a minimal production option: it reads a
//! revocation snapshot written by an external revocation process (for
//! example a job that renders the current revocation list into a mounted
//! file, replacing it atomically) and fails closed whenever that snapshot
//! is missing, unparseable, or past its `valid_until`.
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "issued_at": "2026-06-01T12:00:00Z",
//!   "valid_until": "2026-06-01T12:05:00Z",
//!   "revoked_authority_ids": ["<uuid>"],
//!   "revoked_agent_key_fingerprints": ["<64 hex>"],
//!   "revoked_authority_digests": ["<64 hex>"]
//! }
//! ```
//!
//! The snapshot is re-read at most every `reload_interval`; a revocation
//! therefore takes effect for new checks within `reload_interval`, and a
//! lease already granted stays valid for at most `lease`. All time
//! comparisons use the engine's (trusted) clock passed to `check`.

use praetore_core::{
    AuthorityId, FreshnessError, FreshnessLease, FreshnessProvider,
    canonical::parse_json_rejecting_duplicates, identity::AgentKeyFingerprint,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::PathBuf,
    sync::Mutex,
    time::{Duration as StdDuration, Instant},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const MAX_SNAPSHOT_BYTES: u64 = 8 * 1_048_576;
const MAX_LIST_ENTRIES: usize = 200_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFile {
    schema_version: u8,
    issued_at: String,
    valid_until: String,
    revoked_authority_ids: Vec<Uuid>,
    revoked_agent_key_fingerprints: Vec<String>,
    revoked_authority_digests: Vec<String>,
}

#[derive(Debug)]
struct Snapshot {
    issued_at: OffsetDateTime,
    valid_until: OffsetDateTime,
    revoked_authority_ids: HashSet<Uuid>,
    revoked_agent_key_fingerprints: HashSet<String>,
    revoked_authority_digests: HashSet<String>,
}

struct Loaded {
    read_at: Instant,
    snapshot: Snapshot,
}

/// Timing limits of a [`FileFreshnessProvider`].
#[derive(Debug, Clone, Copy)]
pub struct FileFreshnessLimits {
    /// Maximum age of the in-memory copy before the file is read again.
    pub reload_interval: StdDuration,
    /// Maximum lease granted per check (also capped by `valid_until`).
    pub lease: Duration,
    /// Maximum `valid_until - issued_at` accepted for one snapshot, so a
    /// single snapshot cannot stay authoritative indefinitely.
    pub max_snapshot_validity: Duration,
}

impl Default for FileFreshnessLimits {
    fn default() -> Self {
        Self {
            reload_interval: StdDuration::from_secs(5),
            lease: Duration::seconds(30),
            max_snapshot_validity: Duration::hours(1),
        }
    }
}

pub struct FileFreshnessProvider {
    path: PathBuf,
    policy_digest: String,
    limits: FileFreshnessLimits,
    state: Mutex<State>,
}

struct State {
    loaded: Option<Loaded>,
    /// Newest `issued_at` ever loaded. An older snapshot (rollback by a stale
    /// sync or a restored backup) would undo revocations, so it is refused.
    newest_issued_at: Option<OffsetDateTime>,
}

impl FileFreshnessProvider {
    /// Fails if the snapshot cannot be read and parsed now. A snapshot that
    /// is already past `valid_until` is accepted at startup (checks fail
    /// closed until it is refreshed).
    pub fn new(
        path: impl Into<PathBuf>,
        policy_digest: impl Into<String>,
        limits: FileFreshnessLimits,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if limits.reload_interval.is_zero()
            || limits.lease <= Duration::ZERO
            || limits.max_snapshot_validity <= Duration::ZERO
        {
            return Err("freshness file limits must be greater than zero".into());
        }
        let provider = Self {
            path: path.into(),
            policy_digest: policy_digest.into(),
            limits,
            state: Mutex::new(State {
                loaded: None,
                newest_issued_at: None,
            }),
        };
        let snapshot = provider.read_snapshot()?;
        *provider
            .state
            .lock()
            .map_err(|_| "freshness state lock poisoned")? = State {
            newest_issued_at: Some(snapshot.issued_at),
            loaded: Some(Loaded {
                read_at: Instant::now(),
                snapshot,
            }),
        };
        Ok(provider)
    }

    fn read_snapshot(&self) -> Result<Snapshot, Box<dyn std::error::Error>> {
        let metadata = fs::metadata(&self.path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "freshness snapshot must be a non-empty file no larger than {MAX_SNAPSHOT_BYTES} bytes"
            )
            .into());
        }
        // The file may be replaced after the metadata check: bound the read
        // itself, not only the size reported by `metadata`.
        let mut contents = String::new();
        fs::File::open(&self.path)?
            .take(MAX_SNAPSHOT_BYTES + 1)
            .read_to_string(&mut contents)?;
        if contents.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "freshness snapshot must be no larger than {MAX_SNAPSHOT_BYTES} bytes"
            )
            .into());
        }
        parse_snapshot(&contents, self.limits.max_snapshot_validity)
    }

    fn with_current_snapshot<T>(
        &self,
        check: impl FnOnce(&Snapshot) -> Result<T, FreshnessError>,
    ) -> Result<T, FreshnessError> {
        let mut state = self.state.lock().map_err(|_| FreshnessError::Unavailable)?;
        let stale = state
            .loaded
            .as_ref()
            .is_none_or(|loaded| loaded.read_at.elapsed() >= self.limits.reload_interval);
        if stale {
            let read = self.read_snapshot().and_then(|snapshot| {
                if state
                    .newest_issued_at
                    .is_some_and(|newest| snapshot.issued_at < newest)
                {
                    Err("freshness snapshot is older than one already loaded (rollback)".into())
                } else {
                    Ok(snapshot)
                }
            });
            match read {
                Ok(snapshot) => {
                    state.newest_issued_at = Some(snapshot.issued_at);
                    state.loaded = Some(Loaded {
                        read_at: Instant::now(),
                        snapshot,
                    });
                }
                Err(error) => {
                    // Fail closed: never keep serving a snapshot that can no
                    // longer be read back.
                    state.loaded = None;
                    tracing::warn!(%error, path = %self.path.display(), "freshness snapshot unavailable");
                    return Err(FreshnessError::Unavailable);
                }
            }
        }
        let loaded = state.loaded.as_ref().ok_or(FreshnessError::Unavailable)?;
        check(&loaded.snapshot)
    }

    fn lease(
        &self,
        snapshot: &Snapshot,
        agent: &AgentKeyFingerprint,
        authority_id: &AuthorityId,
        authority_digest: Option<&str>,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        // A snapshot issued in the future or already past its validity says
        // nothing reliable about now: unavailable, not expired, so approved
        // executions stay retryable.
        if now < snapshot.issued_at || now >= snapshot.valid_until {
            return Err(FreshnessError::Unavailable);
        }
        if policy_digest != self.policy_digest {
            return Err(FreshnessError::Revoked);
        }
        let authority_uuid = serde_json::to_value(authority_id)
            .ok()
            .and_then(|value| value.as_str().and_then(|id| Uuid::parse_str(id).ok()))
            .ok_or(FreshnessError::InvalidResponse)?;
        if snapshot.revoked_authority_ids.contains(&authority_uuid)
            || snapshot
                .revoked_agent_key_fingerprints
                .contains(&agent.to_hex())
            || authority_digest
                .is_some_and(|digest| snapshot.revoked_authority_digests.contains(digest))
        {
            return Err(FreshnessError::Revoked);
        }
        let valid_until = now
            .checked_add(self.limits.lease)
            .ok_or(FreshnessError::InvalidResponse)?
            .min(snapshot.valid_until);
        Ok(FreshnessLease { valid_until })
    }
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_snapshot(
    document: &str,
    max_validity: Duration,
) -> Result<Snapshot, Box<dyn std::error::Error>> {
    let value = parse_json_rejecting_duplicates(document)?;
    let file: SnapshotFile = serde_json::from_value(value)?;
    if file.schema_version != 1 {
        return Err("freshness snapshot has an unsupported schema version".into());
    }
    let issued_at = OffsetDateTime::parse(&file.issued_at, &Rfc3339)?;
    let valid_until = OffsetDateTime::parse(&file.valid_until, &Rfc3339)?;
    if valid_until <= issued_at || valid_until - issued_at > max_validity {
        return Err("freshness snapshot validity window is empty or too long".into());
    }
    if file.revoked_authority_ids.len() > MAX_LIST_ENTRIES
        || file.revoked_agent_key_fingerprints.len() > MAX_LIST_ENTRIES
        || file.revoked_authority_digests.len() > MAX_LIST_ENTRIES
    {
        return Err("freshness snapshot revocation lists are too large".into());
    }
    if !file
        .revoked_agent_key_fingerprints
        .iter()
        .chain(&file.revoked_authority_digests)
        .all(|value| canonical_digest(value))
    {
        return Err("freshness snapshot digests must be 64 lowercase hex characters".into());
    }
    Ok(Snapshot {
        issued_at,
        valid_until,
        revoked_authority_ids: file.revoked_authority_ids.into_iter().collect(),
        revoked_agent_key_fingerprints: file.revoked_agent_key_fingerprints.into_iter().collect(),
        revoked_authority_digests: file.revoked_authority_digests.into_iter().collect(),
    })
}

impl FreshnessProvider for FileFreshnessProvider {
    fn check(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &AuthorityId,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        self.with_current_snapshot(|snapshot| {
            self.lease(snapshot, agent, authority_id, None, policy_digest, now)
        })
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if !canonical_digest(authority_digest) {
            return Err(FreshnessError::InvalidResponse);
        }
        self.with_current_snapshot(|snapshot| {
            self.lease(
                snapshot,
                agent,
                authority_id,
                Some(authority_digest),
                policy_digest,
                now,
            )
        })
    }
}

/// Development-only provider: grants a 30 s lease for the configured policy
/// and never checks revocation. The service refuses to use it with the
/// `http` and `sandbox` adapters.
pub struct DemoFreshnessProvider {
    policy_digest: String,
}

impl DemoFreshnessProvider {
    pub fn new(policy_digest: impl Into<String>) -> Self {
        Self {
            policy_digest: policy_digest.into(),
        }
    }
}

impl FreshnessProvider for DemoFreshnessProvider {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if policy_digest != self.policy_digest {
            return Err(FreshnessError::Revoked);
        }
        Ok(FreshnessLease {
            valid_until: now + Duration::seconds(30),
        })
    }

    fn check_authority(
        &self,
        agent: &AgentKeyFingerprint,
        authority_id: &AuthorityId,
        authority_digest: &str,
        policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        if authority_digest.len() != 64
            || !authority_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || policy_digest != self.policy_digest
        {
            return Err(FreshnessError::InvalidResponse);
        }
        self.check(agent, authority_id, policy_digest, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use praetore_core::AgentKeyPair;

    const POLICY: &str = "policy-digest";

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let directory =
                std::env::temp_dir().join(format!("praetore-freshness-{name}-{}", Uuid::new_v4()));
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join("freshness.json");
            Self { directory, path }
        }

        fn write(&self, value: serde_json::Value) {
            let temporary = self.directory.join("next.json");
            fs::write(&temporary, value.to_string()).unwrap();
            fs::rename(temporary, &self.path).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-06-01T12:00:00Z", &Rfc3339).unwrap()
    }

    fn snapshot(
        valid_until: &str,
        authorities: &[Uuid],
        agents: &[String],
        digests: &[String],
    ) -> serde_json::Value {
        snapshot_issued_at(
            "2026-06-01T11:59:00Z",
            valid_until,
            authorities,
            agents,
            digests,
        )
    }

    fn snapshot_issued_at(
        issued_at: &str,
        valid_until: &str,
        authorities: &[Uuid],
        agents: &[String],
        digests: &[String],
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "revoked_authority_ids": authorities,
            "revoked_agent_key_fingerprints": agents,
            "revoked_authority_digests": digests,
        })
    }

    fn immediate_reload() -> FileFreshnessLimits {
        FileFreshnessLimits {
            reload_interval: StdDuration::from_nanos(1),
            ..FileFreshnessLimits::default()
        }
    }

    fn authority_id() -> (AuthorityId, Uuid) {
        let id = AuthorityId::new();
        let uuid = serde_json::to_value(&id)
            .unwrap()
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        (id, uuid)
    }

    fn fingerprint() -> AgentKeyFingerprint {
        AgentKeyFingerprint::from_verified_key(&AgentKeyPair::generate().public_key())
    }

    #[test]
    fn lease_is_bounded_by_configured_lease_and_snapshot_validity() {
        let fixture = Fixture::new("lease");
        fixture.write(snapshot("2026-06-01T12:00:10Z", &[], &[], &[]));
        let provider =
            FileFreshnessProvider::new(&fixture.path, POLICY, immediate_reload()).unwrap();
        let (authority, _) = authority_id();
        let lease = provider
            .check_authority(&fingerprint(), &authority, &"a".repeat(64), POLICY, now())
            .unwrap();
        assert_eq!(lease.valid_until, now() + Duration::seconds(10));
        assert_eq!(
            provider.check(&fingerprint(), &authority, "other-policy", now()),
            Err(FreshnessError::Revoked)
        );
    }

    #[test]
    fn revoked_authority_agent_or_digest_is_refused() {
        let fixture = Fixture::new("revoked");
        let (authority, authority_uuid) = authority_id();
        let agent = fingerprint();
        fixture.write(snapshot("2026-06-01T12:05:00Z", &[], &[], &[]));
        let provider =
            FileFreshnessProvider::new(&fixture.path, POLICY, immediate_reload()).unwrap();
        assert!(provider.check(&agent, &authority, POLICY, now()).is_ok());

        fixture.write(snapshot(
            "2026-06-01T12:05:00Z",
            &[authority_uuid],
            &[],
            &[],
        ));
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Revoked)
        );
        fixture.write(snapshot(
            "2026-06-01T12:05:00Z",
            &[],
            &[agent.to_hex()],
            &[],
        ));
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Revoked)
        );
        let digest = "b".repeat(64);
        fixture.write(snapshot(
            "2026-06-01T12:05:00Z",
            &[],
            &[],
            std::slice::from_ref(&digest),
        ));
        assert_eq!(
            provider.check_authority(&agent, &authority, &digest, POLICY, now()),
            Err(FreshnessError::Revoked)
        );
        assert!(
            provider
                .check_authority(&agent, &authority, &"c".repeat(64), POLICY, now())
                .is_ok()
        );
    }

    #[test]
    fn missing_stale_or_unparseable_snapshot_fails_closed() {
        let fixture = Fixture::new("fail-closed");
        assert!(
            FileFreshnessProvider::new(&fixture.path, POLICY, immediate_reload()).is_err(),
            "a missing snapshot must refuse startup"
        );
        fixture.write(snapshot("2026-06-01T12:05:00Z", &[], &[], &[]));
        let provider =
            FileFreshnessProvider::new(&fixture.path, POLICY, immediate_reload()).unwrap();
        let (authority, _) = authority_id();
        let agent = fingerprint();
        assert!(provider.check(&agent, &authority, POLICY, now()).is_ok());

        // Stale: the engine clock is past valid_until.
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now() + Duration::minutes(5)),
            Err(FreshnessError::Unavailable)
        );
        // Issued in the future relative to the engine clock.
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now() - Duration::minutes(5)),
            Err(FreshnessError::Unavailable)
        );
        // Unparseable, and then missing: never fall back to the old copy.
        fs::write(&fixture.path, "{not json").unwrap();
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Unavailable)
        );
        fixture.write(snapshot("2026-06-01T12:05:00Z", &[], &[], &[]));
        assert!(provider.check(&agent, &authority, POLICY, now()).is_ok());
        fs::remove_file(&fixture.path).unwrap();
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Unavailable)
        );
    }

    #[test]
    fn snapshot_parsing_is_strict() {
        let limit = Duration::hours(1);
        let valid = snapshot("2026-06-01T12:05:00Z", &[], &[], &[]);
        assert!(parse_snapshot(&valid.to_string(), limit).is_ok());
        let too_long = snapshot("2026-06-01T14:00:00Z", &[], &[], &[]);
        assert!(parse_snapshot(&too_long.to_string(), limit).is_err());
        let empty_window = snapshot("2026-06-01T11:59:00Z", &[], &[], &[]);
        assert!(parse_snapshot(&empty_window.to_string(), limit).is_err());
        let uppercase = snapshot("2026-06-01T12:05:00Z", &[], &["A".repeat(64)], &[]);
        assert!(parse_snapshot(&uppercase.to_string(), limit).is_err());
        let mut unknown = valid.clone();
        unknown["extra"] = serde_json::json!(1);
        assert!(parse_snapshot(&unknown.to_string(), limit).is_err());
        let duplicate = valid.to_string().replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(parse_snapshot(&duplicate, limit).is_err());
    }

    #[test]
    fn reload_interval_bounds_how_long_an_old_copy_is_used() {
        let fixture = Fixture::new("reload");
        fixture.write(snapshot("2026-06-01T12:05:00Z", &[], &[], &[]));
        let provider = FileFreshnessProvider::new(
            &fixture.path,
            POLICY,
            FileFreshnessLimits {
                reload_interval: StdDuration::from_millis(300),
                ..FileFreshnessLimits::default()
            },
        )
        .unwrap();
        let (authority, authority_uuid) = authority_id();
        let agent = fingerprint();
        fixture.write(snapshot(
            "2026-06-01T12:05:00Z",
            &[authority_uuid],
            &[],
            &[],
        ));
        // Within the reload interval the cached snapshot is still used...
        assert!(provider.check(&agent, &authority, POLICY, now()).is_ok());
        // ...and once it elapses the revocation applies.
        std::thread::sleep(StdDuration::from_millis(350));
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Revoked)
        );
    }

    #[test]
    fn an_older_snapshot_never_replaces_a_newer_one() {
        let fixture = Fixture::new("rollback");
        let (authority, authority_uuid) = authority_id();
        let agent = fingerprint();
        fixture.write(snapshot_issued_at(
            "2026-06-01T11:59:30Z",
            "2026-06-01T12:05:00Z",
            &[authority_uuid],
            &[],
            &[],
        ));
        let provider =
            FileFreshnessProvider::new(&fixture.path, POLICY, immediate_reload()).unwrap();
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Revoked)
        );
        // A stale copy without the revocation must not undo it.
        fixture.write(snapshot_issued_at(
            "2026-06-01T11:59:00Z",
            "2026-06-01T12:05:00Z",
            &[],
            &[],
            &[],
        ));
        assert_eq!(
            provider.check(&agent, &authority, POLICY, now()),
            Err(FreshnessError::Unavailable)
        );
        // An equally new or newer snapshot is accepted again.
        fixture.write(snapshot_issued_at(
            "2026-06-01T11:59:45Z",
            "2026-06-01T12:05:00Z",
            &[],
            &[],
            &[],
        ));
        assert!(provider.check(&agent, &authority, POLICY, now()).is_ok());
    }
}
