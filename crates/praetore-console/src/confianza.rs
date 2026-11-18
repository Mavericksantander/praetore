//! The attester pins and the local policy the console checks journal
//! evidence against before it shows or offers anything.
//!
//! Loaded once at startup from `PRAETORE_CONSOLE_POLICY_FILE` and
//! `PRAETORE_CONSOLE_ATTESTER_PIN_FILES`, the same files and formats as the
//! compliance package (`RecordedPolicy`, `parse_attester_pin`). A change to
//! those files takes effect when the console is restarted; the compliance
//! package still reads them again at each download.
//!
//! - Inbox: the evidence must be signed by one of the pins and record the
//!   digest of the loaded policy, on top of the integrity hash. Otherwise
//!   the request is not offered.
//! - History with pins: the evidence must be signed by one of the pins. The
//!   policy is not required, so a receipt decided under an earlier policy
//!   stays readable.
//! - History without pins: integrity hash only, as before.

use crate::{
    ApproverSigner,
    paquete::{MAX_ATTESTER_PINS, MAX_PIN_BYTES, MAX_POLICY_BYTES},
};
use praetore_core::{Evidence, VerifiedPublicKey, policy::RecordedPolicy};
use praetore_replay_postgres::journal_export::parse_attester_pin;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const POLICY_VARIABLE: &str = "PRAETORE_CONSOLE_POLICY_FILE";
pub const PINS_VARIABLE: &str = "PRAETORE_CONSOLE_ATTESTER_PIN_FILES";

/// Attester pins (1 to [`MAX_ATTESTER_PINS`], no repeats) and the local
/// policy. Cheap to clone.
#[derive(Debug, Clone)]
pub struct EvidenceTrust {
    pins: Arc<[VerifiedPublicKey]>,
    policy: Arc<RecordedPolicy>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrustError {
    /// The inbox is configured and these variables are not.
    MissingForInbox(Vec<&'static str>),
    NoPins,
    TooManyPins,
    /// The policy file cannot be read or is not a policy.
    Policy,
    /// Pin at this position (from 1) cannot be read, is not a pin, or
    /// repeats an earlier one.
    Pin(usize),
    /// Pin at this position is the approver's own key.
    PinIsApproverKey(usize),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingForInbox(names) => write!(
                f,
                "la bandeja de aprobaciones necesita también {}: sin la política y los pins del atestador no puede verificar la evidencia",
                names.join(" y ")
            ),
            Self::NoPins => write!(f, "{PINS_VARIABLE} necesita al menos un pin"),
            Self::TooManyPins => write!(
                f,
                "{PINS_VARIABLE} acepta a lo más {MAX_ATTESTER_PINS} pins"
            ),
            Self::Policy => write!(
                f,
                "el archivo de {POLICY_VARIABLE} no se pudo leer como política"
            ),
            Self::Pin(position) => write!(
                f,
                "el pin {position} de {PINS_VARIABLE} no se pudo leer, no es un pin o está repetido"
            ),
            Self::PinIsApproverKey(position) => write!(
                f,
                "el pin {position} de {PINS_VARIABLE} es la clave del aprobador, no la del atestador"
            ),
        }
    }
}

impl std::error::Error for TrustError {}

/// With the inbox on, both trust variables are required. `Ok` when the
/// inbox is off or both are present; the error names what is missing.
pub fn require_for_inbox(
    inbox_configured: bool,
    policy: Option<&OsStr>,
    pins: Option<&OsStr>,
) -> Result<(), TrustError> {
    if !inbox_configured {
        return Ok(());
    }
    let mut missing = Vec::new();
    if policy.is_none_or(OsStr::is_empty) {
        missing.push(POLICY_VARIABLE);
    }
    if pins.is_none_or(OsStr::is_empty) {
        missing.push(PINS_VARIABLE);
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(TrustError::MissingForInbox(missing))
    }
}

impl EvidenceTrust {
    pub fn new(pins: Vec<VerifiedPublicKey>, policy: RecordedPolicy) -> Result<Self, TrustError> {
        if pins.is_empty() {
            return Err(TrustError::NoPins);
        }
        if pins.len() > MAX_ATTESTER_PINS {
            return Err(TrustError::TooManyPins);
        }
        for (index, pin) in pins.iter().enumerate() {
            if pins[..index].contains(pin) {
                return Err(TrustError::Pin(index + 1));
            }
        }
        Ok(Self {
            pins: pins.into(),
            policy: Arc::new(policy),
        })
    }

    /// Reads the policy and the pins once. A pin that is the approver's own
    /// key is refused, as the compliance package does.
    pub fn load(
        policy_file: &Path,
        pin_files: &[PathBuf],
        approver: Option<&ApproverSigner>,
    ) -> Result<Self, TrustError> {
        if pin_files.is_empty() {
            return Err(TrustError::NoPins);
        }
        if pin_files.len() > MAX_ATTESTER_PINS {
            return Err(TrustError::TooManyPins);
        }
        let policy_json =
            read_public_file(policy_file, MAX_POLICY_BYTES).map_err(|()| TrustError::Policy)?;
        let policy = RecordedPolicy::from_json(&policy_json).map_err(|_| TrustError::Policy)?;
        let mut pins = Vec::with_capacity(pin_files.len());
        for (index, path) in pin_files.iter().enumerate() {
            let text =
                read_public_file(path, MAX_PIN_BYTES).map_err(|()| TrustError::Pin(index + 1))?;
            let pin = parse_attester_pin(&text).map_err(|_| TrustError::Pin(index + 1))?;
            if approver.is_some_and(|signer| signer.is_key_material(&pin.as_bytes())) {
                return Err(TrustError::PinIsApproverKey(index + 1));
            }
            pins.push(pin);
        }
        Self::new(pins, policy)
    }

    pub fn pins(&self) -> &[VerifiedPublicKey] {
        &self.pins
    }

    /// Inbox rule: integrity, the signature of one of the pins, and the
    /// digest of the loaded policy.
    pub fn admits_pending(&self, evidence: &Evidence) -> bool {
        signed_by_a_pin(evidence, &self.pins)
            && evidence.verify_recorded_policy(&self.policy).is_ok()
    }
}

/// Integrity and the attester signature of at least one of `pins`
/// (`Evidence::verify_attester_signature` checks both).
pub fn signed_by_a_pin(evidence: &Evidence, pins: &[VerifiedPublicKey]) -> bool {
    pins.iter()
        .any(|pin| evidence.verify_attester_signature(pin).is_ok())
}

/// Opens a public file (policy, pin) without following a final symlink and
/// without blocking on a FIFO, then checks the open file: a regular file of
/// at most `max` bytes, UTF-8.
#[cfg(unix)]
fn read_public_file(path: &Path, max: u64) -> Result<String, ()> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let flags =
        rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_file() || metadata.len() > max {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() as u64 > max {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

#[cfg(not(unix))]
fn read_public_file(_path: &Path, _max: u64) -> Result<String, ()> {
    Err(())
}
