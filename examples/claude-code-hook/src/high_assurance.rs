//! HighAssurance evaluation for the hook: a durable local replay guard, a
//! local freshness provider, and the engine built from the hook state.
//!
//! Every receipt the hook writes is HighAssurance evidence: it records the
//! engine's signed decision time (`decided_at`), so a verifier can check the
//! authority and the issuer pin at the moment of the decision instead of at
//! its own clock (`praetore-verify evidence --require-decision-time`).

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use praetore_core::{
    AgentKeyFingerprint, AuthorityId, EvidenceAttesterKey, FreshnessError, FreshnessLease,
    FreshnessProvider, HighAssuranceConfig, Policy, ReplayGuard, ReplayGuardError,
    TrustedAuthorityIssuer, engine::AuthorizationEngine,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::BoxError;

/// Audience every hook intent is signed for, and the only one the engine
/// accepts.
pub(crate) const AUDIENCE: &str = "praetore-claude-hook";
/// Directory of the replay store, inside the hook state. `init` creates it;
/// a state without it was created before HighAssurance receipts.
pub(crate) const REPLAY_DIR: &str = "replay";
/// Lifetime of a signed intent. The hook signs and evaluates in the same
/// process, so it only has to cover that one evaluation.
pub(crate) const INTENT_LIFETIME: Duration = Duration::seconds(60);
/// Lease granted by [`LocalFreshness`], also the engine maximum.
const FRESHNESS_LEASE: Duration = Duration::seconds(60);
/// Longest authority `init` issues (`--valid-days`), plus the five minutes
/// of `not_before` slack it adds.
pub(crate) const MAX_VALID_DAYS: i64 = 3650;

/// Durable, fail-closed, one-time claim store on the local filesystem.
///
/// One claim is one file, `replay/<tenant>/<agent>/<request>`, created with
/// `create_new` (`O_CREAT | O_EXCL`). The create is the claim: the kernel
/// guarantees that of several processes creating the same name, exactly one
/// succeeds and the others get `AlreadyExists`. That is the only shared
/// state, so no lock is needed: a lock would be a second mechanism that also
/// has to fail closed, and it would add nothing to the guarantee.
///
/// Durability: the claim file and its directory are `fsync`ed before the
/// claim is reported. Claims are never removed (the engine's contract: a
/// removed claim can make an old signed request usable again).
///
/// Fail closed: any error other than `AlreadyExists` (missing or replaced
/// store, a symlink or a non-directory in the path, permissions open to
/// group or others, a full disk, a failed `fsync`) is
/// [`ReplayGuardError::Unavailable`], and the engine then returns no
/// evidence. A claim whose file was created but whose `fsync` failed stays
/// claimed: the request is refused and cannot be retried, which is the safe
/// side.
///
/// Requirement: the state directory must be on a local filesystem with
/// atomic exclusive create (any local POSIX filesystem; not NFSv2).
pub(crate) struct FileReplayGuard {
    root: PathBuf,
}

impl FileReplayGuard {
    pub(crate) fn new(state: &Path) -> Self {
        Self {
            root: state.join(REPLAY_DIR),
        }
    }

    fn claim(&self, tenant: Uuid, agent: Uuid, request: Uuid) -> Result<bool, io::Error> {
        check_private_directory(&self.root)?;
        let tenant_dir = self.root.join(tenant.to_string());
        let agent_dir = tenant_dir.join(agent.to_string());
        for directory in [&tenant_dir, &agent_dir] {
            create_private_directory_if_missing(directory)?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = match options.open(agent_dir.join(request.to_string())) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => return Err(error),
        };
        file.sync_all()?;
        // The new directory entries must survive a crash too.
        for directory in [&agent_dir, &tenant_dir, &self.root] {
            fs::File::open(directory)?.sync_all()?;
        }
        Ok(true)
    }
}

impl ReplayGuard for FileReplayGuard {
    fn claim_once(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        request_id: Uuid,
    ) -> Result<(), ReplayGuardError> {
        match self.claim(tenant_id, agent_id, request_id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ReplayGuardError::AlreadyClaimed),
            Err(_) => Err(ReplayGuardError::Unavailable),
        }
    }
}

/// A real directory (not a symlink) that only its owner can access.
fn check_private_directory(path: &Path) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(format!(
                "{} is accessible by group/others",
                path.display()
            )));
        }
    }
    Ok(())
}

fn create_private_directory_if_missing(path: &Path) -> Result<(), io::Error> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => check_private_directory(path),
        Err(error) => Err(error),
    }
}

/// Local freshness. The hook has no revocation source: its authorities are
/// issued by a local issuer whose key is discarded at `init`. This provider
/// grants a one-minute lease and rejects malformed authority digests; it
/// does not detect revocation. Re-run `init` to replace every authority.
pub(crate) struct LocalFreshness;

impl FreshnessProvider for LocalFreshness {
    fn check(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        _policy_digest: &str,
        _now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        // HighAssurance calls `check_authority`; this unbound form is refused.
        Err(FreshnessError::InvalidResponse)
    }

    fn check_authority(
        &self,
        _agent: &AgentKeyFingerprint,
        _authority_id: &AuthorityId,
        authority_digest: &str,
        _policy_digest: &str,
        now: OffsetDateTime,
    ) -> Result<FreshnessLease, FreshnessError> {
        let well_formed = authority_digest.len() == 64
            && authority_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed {
            return Err(FreshnessError::InvalidResponse);
        }
        Ok(FreshnessLease {
            valid_until: now + FRESHNESS_LEASE,
        })
    }
}

/// Refuses hook state created before HighAssurance receipts (no replay
/// store), with the step that fixes it.
pub(crate) fn check_state(directory: &Path) -> Result<(), BoxError> {
    let replay = directory.join(REPLAY_DIR);
    match fs::symlink_metadata(&replay) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(format!(
            "hook state at {} predates HighAssurance receipts: it has no replay store ({REPLAY_DIR}/). Run `praetore-claude-hook init` into a new directory and point the hook at it; receipts already written still verify with `verify`",
            directory.display()
        )
        .into()),
        _ => check_private_directory(&replay)
            .map_err(|error| format!("replay store unavailable: {error}").into()),
    }
}

/// The HighAssurance engine for one hook invocation: the policy as loaded
/// (its digest is what the intent signs), the pinned issuer, the attester
/// key, the replay store in `directory` and local freshness.
pub(crate) fn engine(
    directory: &Path,
    policy: Policy,
    issuer: TrustedAuthorityIssuer,
    attester: EvidenceAttesterKey,
) -> Result<AuthorizationEngine, BoxError> {
    check_state(directory)?;
    let config = HighAssuranceConfig::new(policy.digest()?, vec![issuer], attester)?
        .with_audience(AUDIENCE)
        .with_max_intent_lifetime(INTENT_LIFETIME)
        .with_max_authority_lifetime(Duration::days(MAX_VALID_DAYS) + Duration::minutes(5))
        .with_max_freshness_lease(FRESHNESS_LEASE)
        .with_replay_guard(Arc::new(FileReplayGuard::new(directory)))
        .with_freshness_provider(Arc::new(LocalFreshness));
    AuthorizationEngine::production(policy, config).map_err(|error| {
        format!(
            "cannot start the HighAssurance engine ({}): {error}",
            error.code()
        )
        .into()
    })
}
