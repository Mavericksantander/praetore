//! Where the gateway's two signing keys come from (SAF-11, decisions 1-3).
//!
//! Each key (the evidence attester and the execution attester) has exactly
//! one source:
//!
//! | Source | Variables | Allowed |
//! |---|---|---|
//! | Hex in the environment | `..._KEY_HEX` | `local-demo`; `http`/`sandbox` only with [`ENV_KEY_OPT_IN`] |
//! | File | `..._KEY_FILE` | always |
//! | PKCS#11 token | `..._PKCS11_KEY_LABEL` plus `PRAETORE_GATEWAY_PKCS11_*` | builds with the `pkcs11` feature |
//!
//! Setting more than one source for a key, or none, is an error. Nothing
//! here logs or returns key material, PINs or file contents: errors name the
//! variable, never its value.

use praetore_core::{LocalSigner, SignatureAlgorithm, Signer};
use std::{fs, path::Path, sync::Arc};
use zeroize::Zeroizing;

/// Explicit opt-in that lets `http`/`sandbox` read a signing key from a
/// `..._KEY_HEX` variable. The only accepted value is [`ENV_KEY_OPT_IN_VALUE`].
pub const ENV_KEY_OPT_IN: &str = "PRAETORE_GATEWAY_DANGEROUSLY_ALLOW_SIGNING_KEYS_IN_ENV";
pub const ENV_KEY_OPT_IN_VALUE: &str = "yes";
/// `ed25519` (default) or `ed25519-sha256-envelope`, for evidence only.
pub const EVIDENCE_ALGORITHM_VAR: &str = "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_ALGORITHM";
pub const PKCS11_MODULE_VAR: &str = "PRAETORE_GATEWAY_PKCS11_MODULE";
pub const PKCS11_TOKEN_LABEL_VAR: &str = "PRAETORE_GATEWAY_PKCS11_TOKEN_LABEL";
pub const PKCS11_PIN_FILE_VAR: &str = "PRAETORE_GATEWAY_PKCS11_PIN_FILE";

const MAX_SECRET_FILE_BYTES: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    EvidenceAttester,
    ExecutionAttester,
}

impl KeyRole {
    pub fn hex_var(self) -> &'static str {
        match self {
            Self::EvidenceAttester => "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX",
            Self::ExecutionAttester => "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX",
        }
    }

    pub fn file_var(self) -> &'static str {
        match self {
            Self::EvidenceAttester => "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_FILE",
            Self::ExecutionAttester => "PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_FILE",
        }
    }

    pub fn pkcs11_label_var(self) -> &'static str {
        match self {
            Self::EvidenceAttester => "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_PKCS11_KEY_LABEL",
            Self::ExecutionAttester => "PRAETORE_GATEWAY_EXECUTION_ATTESTER_PKCS11_KEY_LABEL",
        }
    }

    /// The pinned public key of a PKCS#11 key (required with a label).
    pub fn pkcs11_public_key_var(self) -> &'static str {
        match self {
            Self::EvidenceAttester => "PRAETORE_GATEWAY_EVIDENCE_ATTESTER_PKCS11_PUBLIC_KEY_FILE",
            Self::ExecutionAttester => "PRAETORE_GATEWAY_EXECUTION_ATTESTER_PKCS11_PUBLIC_KEY_FILE",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::EvidenceAttester => "evidence attester",
            Self::ExecutionAttester => "execution attester",
        }
    }
}

/// Where a loaded key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    EnvironmentHex,
    File,
    Pkcs11,
}

impl KeySource {
    fn execution_key_id_prefix(self) -> &'static str {
        match self {
            // Unchanged from before SAF-11, so existing verifier
            // configuration keeps working.
            Self::EnvironmentHex => "local-demo",
            Self::File => "local",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

pub struct LoadedSigner {
    pub signer: Arc<dyn Signer>,
    pub source: KeySource,
}

impl LoadedSigner {
    /// The execution attestation `key_id`: `<source>-<public key hex>`
    /// (`local-demo-...` for a hex variable, `local-...` for a file,
    /// `pkcs11-...` for a token).
    pub fn execution_key_id(&self) -> String {
        format!(
            "{}-{}",
            self.source.execution_key_id_prefix(),
            hex::encode(self.signer.verifying_key().as_bytes())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKeyError {
    Missing(KeyRole),
    Ambiguous(KeyRole),
    EnvKeyRefused(KeyRole),
    InvalidOptIn,
    InvalidHex(&'static str),
    SecretFile {
        var: &'static str,
        reason: &'static str,
    },
    InvalidAlgorithm,
    Pkcs11Unavailable(&'static str),
    Pkcs11Config(&'static str),
    Pkcs11(String),
    SameKeyForBothRoles,
}

impl std::fmt::Display for SigningKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(role) => write!(
                f,
                "the {} key is required: set {} (or {})",
                role.description(),
                role.file_var(),
                role.pkcs11_label_var()
            ),
            Self::Ambiguous(role) => write!(
                f,
                "set exactly one of {}, {} and {}",
                role.hex_var(),
                role.file_var(),
                role.pkcs11_label_var()
            ),
            Self::EnvKeyRefused(role) => write!(
                f,
                "the http and sandbox adapters refuse a signing key in {}: use {} or a PKCS#11 key \
                 (or set {ENV_KEY_OPT_IN}={ENV_KEY_OPT_IN_VALUE} to accept the risk)",
                role.hex_var(),
                role.file_var()
            ),
            Self::InvalidOptIn => write!(
                f,
                "{ENV_KEY_OPT_IN} accepts only the value {ENV_KEY_OPT_IN_VALUE}"
            ),
            Self::InvalidHex(var) => write!(
                f,
                "{var} must contain exactly 64 lowercase hexadecimal characters (a 32-byte key)"
            ),
            Self::SecretFile { var, reason } => write!(f, "the file named by {var} {reason}"),
            Self::InvalidAlgorithm => write!(
                f,
                "{EVIDENCE_ALGORITHM_VAR} must be ed25519 or ed25519-sha256-envelope"
            ),
            Self::Pkcs11Unavailable(var) => write!(
                f,
                "{var} is set but this binary was built without the pkcs11 feature"
            ),
            Self::Pkcs11Config(var) => write!(f, "{var} is required for PKCS#11 keys"),
            Self::Pkcs11(message) => write!(f, "PKCS#11 signer: {message}"),
            Self::SameKeyForBothRoles => write!(
                f,
                "the evidence attester and the execution attester must be different keys"
            ),
        }
    }
}

impl std::error::Error for SigningKeyError {}

/// Reads a 32-byte key from a file: exactly 64 lowercase hex characters,
/// optionally followed by one newline. The file must be a regular file of
/// at most 256 bytes and, on Unix, not accessible by group or others (mode
/// `0600` or `0400`; for a Kubernetes Secret, `defaultMode: 0400`).
pub fn read_secret_key_file(
    path: &Path,
    var: &'static str,
) -> Result<Zeroizing<[u8; 32]>, SigningKeyError> {
    let contents = read_secret_file(path, var)?;
    let text = contents.strip_suffix(b"\n").unwrap_or(contents.as_slice());
    decode_key_hex(text).ok_or(SigningKeyError::InvalidHex(var))
}

fn read_secret_file(path: &Path, var: &'static str) -> Result<Zeroizing<Vec<u8>>, SigningKeyError> {
    read_limited_file(path, var, true)
}

/// Opens the last path component without following a symlink and, on Unix,
/// without blocking on a FIFO.
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::open(path)
    }
}

/// Opens `path` once and checks and reads that same open file: a regular
/// file (`fstat` on the descriptor), at most 256 bytes (also enforced while
/// reading), and with `private`, not accessible by group or others. A
/// symlink as the last component is refused (`O_NOFOLLOW`); symlinks in
/// the directories above it are followed.
fn read_limited_file(
    path: &Path,
    var: &'static str,
    private: bool,
) -> Result<Zeroizing<Vec<u8>>, SigningKeyError> {
    use std::io::Read;
    let error = |reason| SigningKeyError::SecretFile { var, reason };
    let file = open_no_follow(path).map_err(|open_error| {
        #[cfg(unix)]
        if open_error.raw_os_error() == Some(libc::ELOOP) {
            return error("is a symbolic link; name the file itself");
        }
        let _ = open_error;
        error("cannot be read")
    })?;
    let metadata = file.metadata().map_err(|_| error("cannot be read"))?;
    if !metadata.is_file() {
        return Err(error("is not a regular file"));
    }
    if metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(error("is larger than 256 bytes"));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(error(
                "is accessible by group or others; set its mode to 0600 or 0400",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    // Capacity for the limit plus one byte: no reallocation leaves copies.
    let mut contents = Zeroizing::new(Vec::with_capacity(MAX_SECRET_FILE_BYTES as usize + 1));
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| error("cannot be read"))?;
    if contents.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(error("is larger than 256 bytes"));
    }
    Ok(contents)
}

/// Reads a pinned Ed25519 public key: 64 lowercase hex characters,
/// optionally followed by one newline (the `praetore-verify` pin format).
pub fn read_public_key_file(
    path: &Path,
    var: &'static str,
) -> Result<praetore_core::VerifiedPublicKey, SigningKeyError> {
    let contents = read_limited_file(path, var, false)?;
    let text = contents.strip_suffix(b"\n").unwrap_or(contents.as_slice());
    let bytes = decode_key_hex(text).ok_or(SigningKeyError::InvalidHex(var))?;
    praetore_core::VerifiedPublicKey::from_bytes(bytes.as_slice())
        .map_err(|_| SigningKeyError::InvalidHex(var))
}

fn decode_key_hex(text: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (index, byte) in key.iter_mut().enumerate() {
        let high = lower_hex_value(text[2 * index])?;
        let low = lower_hex_value(text[2 * index + 1])?;
        *byte = (high << 4) | low;
    }
    Some(key)
}

fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Reads `EVIDENCE_ALGORITHM_VAR` (default `ed25519`).
pub fn evidence_algorithm(
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<SignatureAlgorithm, SigningKeyError> {
    match env(EVIDENCE_ALGORITHM_VAR) {
        None => Ok(SignatureAlgorithm::Ed25519),
        Some(value) => {
            SignatureAlgorithm::from_identifier(&value).ok_or(SigningKeyError::InvalidAlgorithm)
        }
    }
}

/// Loads the key for `role`. `production` is true for the `http` and
/// `sandbox` adapters. `env` reads one environment variable.
pub fn load_signer(
    role: KeyRole,
    production: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<LoadedSigner, SigningKeyError> {
    let algorithm = match role {
        KeyRole::EvidenceAttester => evidence_algorithm(env)?,
        // Execution attestations have no algorithm field: always plain
        // Ed25519 over the domain and payload.
        KeyRole::ExecutionAttester => SignatureAlgorithm::Ed25519,
    };
    let hex = env(role.hex_var()).map(Zeroizing::new);
    let file = env(role.file_var());
    let label = env(role.pkcs11_label_var());
    match (hex, file, label) {
        (Some(hex), None, None) => {
            if production {
                match env(ENV_KEY_OPT_IN).as_deref() {
                    Some(ENV_KEY_OPT_IN_VALUE) => {}
                    Some(_) => return Err(SigningKeyError::InvalidOptIn),
                    None => return Err(SigningKeyError::EnvKeyRefused(role)),
                }
            }
            let secret = decode_key_hex(hex.as_bytes())
                .ok_or(SigningKeyError::InvalidHex(role.hex_var()))?;
            Ok(LoadedSigner {
                signer: Arc::new(LocalSigner::from_secret_bytes(&secret).with_algorithm(algorithm)),
                source: KeySource::EnvironmentHex,
            })
        }
        (None, Some(path), None) => {
            let secret = read_secret_key_file(Path::new(&path), role.file_var())?;
            Ok(LoadedSigner {
                signer: Arc::new(LocalSigner::from_secret_bytes(&secret).with_algorithm(algorithm)),
                source: KeySource::File,
            })
        }
        (None, None, Some(label)) => Ok(LoadedSigner {
            signer: pkcs11_signer(role, &label, algorithm, env)?,
            source: KeySource::Pkcs11,
        }),
        (None, None, None) => Err(SigningKeyError::Missing(role)),
        _ => Err(SigningKeyError::Ambiguous(role)),
    }
}

/// Loads the evidence and the execution key and refuses the same key for
/// both: each role keeps its own key, so revoking or rotating one does not
/// silently affect the other.
pub fn load_signers(
    production: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(LoadedSigner, LoadedSigner), SigningKeyError> {
    let evidence = load_signer(KeyRole::EvidenceAttester, production, env)?;
    let execution = load_signer(KeyRole::ExecutionAttester, production, env)?;
    if evidence.signer.verifying_key() == execution.signer.verifying_key() {
        return Err(SigningKeyError::SameKeyForBothRoles);
    }
    Ok((evidence, execution))
}

#[cfg(feature = "pkcs11")]
fn pkcs11_signer(
    role: KeyRole,
    label: &str,
    algorithm: SignatureAlgorithm,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Arc<dyn Signer>, SigningKeyError> {
    let required = |var: &'static str| env(var).ok_or(SigningKeyError::Pkcs11Config(var));
    let module = required(PKCS11_MODULE_VAR)?;
    let token_label = required(PKCS11_TOKEN_LABEL_VAR)?;
    let pin_path = required(PKCS11_PIN_FILE_VAR)?;
    // The public key is pinned: a key pair regenerated in the token under
    // the same label (by anyone with the user PIN) is refused at startup.
    let expected_public_key = read_public_key_file(
        Path::new(&required(role.pkcs11_public_key_var())?),
        role.pkcs11_public_key_var(),
    )?;
    let pin = read_secret_file(Path::new(&pin_path), PKCS11_PIN_FILE_VAR)?;
    let pin = pin.strip_suffix(b"\n").unwrap_or(pin.as_slice());
    let pin = std::str::from_utf8(pin)
        .ok()
        .filter(|pin| !pin.is_empty())
        .ok_or(SigningKeyError::SecretFile {
            var: PKCS11_PIN_FILE_VAR,
            reason: "must contain a non-empty UTF-8 PIN",
        })?;
    let config = praetore_signer_pkcs11::Pkcs11Config {
        module: module.into(),
        token_label,
        key_label: label.to_owned(),
        user_pin: cryptoki_pin(pin),
        algorithm,
        expected_public_key: Some(expected_public_key),
    };
    praetore_signer_pkcs11::Pkcs11Signer::open(&config)
        .map(|signer| Arc::new(signer) as Arc<dyn Signer>)
        .map_err(|error| SigningKeyError::Pkcs11(error.to_string()))
}

#[cfg(feature = "pkcs11")]
fn cryptoki_pin(pin: &str) -> praetore_signer_pkcs11::AuthPin {
    praetore_signer_pkcs11::AuthPin::new(pin.into())
}

#[cfg(not(feature = "pkcs11"))]
fn pkcs11_signer(
    role: KeyRole,
    _label: &str,
    _algorithm: SignatureAlgorithm,
    _env: &dyn Fn(&str) -> Option<String>,
) -> Result<Arc<dyn Signer>, SigningKeyError> {
    Err(SigningKeyError::Pkcs11Unavailable(role.pkcs11_label_var()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SECRET_HEX: &str = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "praetore-signing-keys-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, contents: &[u8], mode: u32) -> String {
            let path = self.0.join(name);
            fs::write(&path, contents).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
            #[cfg(not(unix))]
            let _ = mode;
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn expected_public_key() -> [u8; 32] {
        LocalSigner::from_secret_bytes(&[0x1a; 32])
            .public_key()
            .unwrap()
            .as_bytes()
    }

    #[test]
    fn production_refuses_hex_keys_in_the_environment() {
        for role in [KeyRole::EvidenceAttester, KeyRole::ExecutionAttester] {
            let env = env_of(&[(role.hex_var(), SECRET_HEX)]);
            let error = load_signer(role, true, &env).err().unwrap();
            assert_eq!(error, SigningKeyError::EnvKeyRefused(role));
            let message = error.to_string();
            assert!(message.contains(role.hex_var()));
            assert!(message.contains(role.file_var()));
            assert!(!message.contains(SECRET_HEX));
        }
    }

    #[test]
    fn local_demo_keeps_accepting_hex_keys_with_the_old_key_id() {
        let env = env_of(&[(KeyRole::ExecutionAttester.hex_var(), SECRET_HEX)]);
        let loaded = load_signer(KeyRole::ExecutionAttester, false, &env).unwrap();
        assert_eq!(loaded.source, KeySource::EnvironmentHex);
        assert_eq!(
            loaded.signer.verifying_key().as_bytes(),
            expected_public_key()
        );
        assert_eq!(
            loaded.execution_key_id(),
            format!("local-demo-{}", hex::encode(expected_public_key()))
        );
    }

    #[test]
    fn the_opt_in_needs_its_exact_value() {
        let role = KeyRole::EvidenceAttester;
        let accepted = env_of(&[
            (role.hex_var(), SECRET_HEX),
            (ENV_KEY_OPT_IN, ENV_KEY_OPT_IN_VALUE),
        ]);
        assert!(load_signer(role, true, &accepted).is_ok());
        for value in ["1", "true", "YES", "yes ", ""] {
            let env = env_of(&[(role.hex_var(), SECRET_HEX), (ENV_KEY_OPT_IN, value)]);
            assert_eq!(
                load_signer(role, true, &env).err().unwrap(),
                SigningKeyError::InvalidOptIn
            );
        }
    }

    #[test]
    fn production_loads_keys_from_private_files() {
        let dir = TempDir::new();
        for contents in [SECRET_HEX.to_owned(), format!("{SECRET_HEX}\n")] {
            let path = dir.write("key", contents.as_bytes(), 0o600);
            let env = env_of(&[(KeyRole::EvidenceAttester.file_var(), &path)]);
            let loaded = load_signer(KeyRole::EvidenceAttester, true, &env).unwrap();
            assert_eq!(loaded.source, KeySource::File);
            assert_eq!(
                loaded.signer.verifying_key().as_bytes(),
                expected_public_key()
            );
            assert_eq!(loaded.signer.algorithm(), SignatureAlgorithm::Ed25519);
        }
        let path = dir.write("readonly", SECRET_HEX.as_bytes(), 0o400);
        let env = env_of(&[
            (KeyRole::ExecutionAttester.file_var(), &path),
            // Ignored for the execution key.
            (EVIDENCE_ALGORITHM_VAR, "ed25519-sha256-envelope"),
        ]);
        let loaded = load_signer(KeyRole::ExecutionAttester, true, &env).unwrap();
        assert_eq!(loaded.signer.algorithm(), SignatureAlgorithm::Ed25519);
        assert_eq!(
            loaded.execution_key_id(),
            format!("local-{}", hex::encode(expected_public_key()))
        );
    }

    #[test]
    fn the_evidence_algorithm_is_configurable_and_validated() {
        let dir = TempDir::new();
        let path = dir.write("key", SECRET_HEX.as_bytes(), 0o600);
        let role = KeyRole::EvidenceAttester;
        let env = env_of(&[
            (role.file_var(), &path),
            (EVIDENCE_ALGORITHM_VAR, "ed25519-sha256-envelope"),
        ]);
        assert_eq!(
            load_signer(role, true, &env).unwrap().signer.algorithm(),
            SignatureAlgorithm::Ed25519Sha256Envelope
        );
        let env = env_of(&[
            (role.file_var(), &path),
            (EVIDENCE_ALGORITHM_VAR, "ed25519ph"),
        ]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::InvalidAlgorithm
        );
    }

    #[test]
    #[cfg(unix)]
    fn key_files_readable_by_others_or_malformed_are_rejected_without_leaking() {
        let dir = TempDir::new();
        let role = KeyRole::EvidenceAttester;
        let cases: [(&str, Vec<u8>, u32); 9] = [
            ("group-readable", SECRET_HEX.into(), 0o640),
            ("world-readable", SECRET_HEX.into(), 0o644),
            ("uppercase", SECRET_HEX.to_uppercase().into(), 0o600),
            ("short", SECRET_HEX[..62].into(), 0o600),
            ("long", format!("{SECRET_HEX}00").into(), 0o600),
            ("two-newlines", format!("{SECRET_HEX}\n\n").into(), 0o600),
            ("crlf", format!("{SECRET_HEX}\r\n").into(), 0o600),
            ("spaces", format!(" {SECRET_HEX}").into(), 0o600),
            ("large", vec![b'a'; 300], 0o600),
        ];
        for (name, contents, mode) in cases {
            let path = dir.write(name, &contents, mode);
            let env = env_of(&[(role.file_var(), &path)]);
            let error = load_signer(role, true, &env).err().unwrap();
            let message = error.to_string();
            assert!(message.contains(role.file_var()), "{name}: {message}");
            assert!(
                !message.to_lowercase().contains(&SECRET_HEX[..16]),
                "{name}: {message}"
            );
            assert!(!format!("{error:?}").contains(&SECRET_HEX[..16]), "{name}");
        }
        let env = env_of(&[(role.file_var(), "/nonexistent/praetore-key")]);
        assert!(matches!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile { .. }
        ));
        let env = env_of(&[(role.file_var(), dir.0.to_str().unwrap())]);
        assert!(matches!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile {
                reason: "is not a regular file",
                ..
            }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn key_files_are_opened_once_without_following_a_final_symlink() {
        let dir = TempDir::new();
        let role = KeyRole::EvidenceAttester;
        let real = dir.write("real", SECRET_HEX.as_bytes(), 0o600);
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let env = env_of(&[(role.file_var(), link.to_str().unwrap())]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile {
                var: role.file_var(),
                reason: "is a symbolic link; name the file itself",
            }
        );
        // A symlink to /dev/zero is refused before anything is read.
        let zero = dir.0.join("zero");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        let env = env_of(&[(role.file_var(), zero.to_str().unwrap())]);
        assert!(matches!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile { .. }
        ));
        // A FIFO is refused without blocking.
        let fifo = dir.0.join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let env = env_of(&[(role.file_var(), fifo.to_str().unwrap())]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile {
                var: role.file_var(),
                reason: "is not a regular file",
            }
        );
        // An oversized file is refused.
        let large = dir.write("large", &[b'a'; 4096], 0o600);
        let env = env_of(&[(role.file_var(), &large)]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::SecretFile {
                var: role.file_var(),
                reason: "is larger than 256 bytes",
            }
        );
        // Symlinked directories above the file are followed (the layout of
        // a Kubernetes Secret volume: <mount>/..data/<key>).
        fs::create_dir(dir.0.join("versioned")).unwrap();
        let versioned = dir.0.join("versioned").join("key");
        fs::write(&versioned, SECRET_HEX).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&versioned, fs::Permissions::from_mode(0o400)).unwrap();
        }
        std::os::unix::fs::symlink(dir.0.join("versioned"), dir.0.join("..data")).unwrap();
        let through_dir = dir.0.join("..data").join("key");
        let env = env_of(&[(role.file_var(), through_dir.to_str().unwrap())]);
        assert!(load_signer(role, true, &env).is_ok());
    }

    #[test]
    fn the_same_key_for_evidence_and_execution_is_refused() {
        let dir = TempDir::new();
        let key = dir.write("key", SECRET_HEX.as_bytes(), 0o600);
        let copy = dir.write("copy", SECRET_HEX.as_bytes(), 0o600);
        let env = env_of(&[
            (KeyRole::EvidenceAttester.file_var(), &key),
            (KeyRole::ExecutionAttester.file_var(), &copy),
        ]);
        assert_eq!(
            load_signers(true, &env).err().unwrap(),
            SigningKeyError::SameKeyForBothRoles
        );
        let other = dir.write("other", "2b".repeat(32).as_bytes(), 0o600);
        let env = env_of(&[
            (KeyRole::EvidenceAttester.file_var(), &key),
            (KeyRole::ExecutionAttester.file_var(), &other),
        ]);
        assert!(load_signers(true, &env).is_ok());
    }

    #[test]
    fn malformed_hex_in_the_environment_is_rejected_without_leaking() {
        let role = KeyRole::ExecutionAttester;
        for value in [&SECRET_HEX[..62], &SECRET_HEX.to_uppercase(), "zz"] {
            let env = env_of(&[(role.hex_var(), value)]);
            let error = load_signer(role, false, &env).err().unwrap();
            assert_eq!(error, SigningKeyError::InvalidHex(role.hex_var()));
            assert!(!error.to_string().contains(value));
        }
    }

    #[test]
    fn exactly_one_source_is_required() {
        let dir = TempDir::new();
        let path = dir.write("key", SECRET_HEX.as_bytes(), 0o600);
        let role = KeyRole::EvidenceAttester;
        assert_eq!(
            load_signer(role, false, &env_of(&[])).err().unwrap(),
            SigningKeyError::Missing(role)
        );
        for pairs in [
            vec![
                (role.hex_var(), SECRET_HEX),
                (role.file_var(), path.as_str()),
            ],
            vec![
                (role.file_var(), path.as_str()),
                (role.pkcs11_label_var(), "k"),
            ],
            vec![(role.hex_var(), SECRET_HEX), (role.pkcs11_label_var(), "k")],
        ] {
            assert_eq!(
                load_signer(role, false, &env_of(&pairs)).err().unwrap(),
                SigningKeyError::Ambiguous(role)
            );
        }
    }

    #[test]
    #[cfg(not(feature = "pkcs11"))]
    fn pkcs11_keys_need_the_pkcs11_feature() {
        let role = KeyRole::ExecutionAttester;
        let env = env_of(&[(role.pkcs11_label_var(), "praetore-execution")]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::Pkcs11Unavailable(role.pkcs11_label_var())
        );
    }

    #[test]
    #[cfg(feature = "pkcs11")]
    fn pkcs11_keys_need_module_token_pinned_public_key_and_pin_file() {
        let role = KeyRole::EvidenceAttester;
        let env = env_of(&[(role.pkcs11_label_var(), "praetore-evidence")]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::Pkcs11Config(PKCS11_MODULE_VAR)
        );
        let dir = TempDir::new();
        let pin = dir.write("pin-private", b"1234\n", 0o600);
        // No pinned public key: refused before the token is opened.
        let without_pin = [
            (role.pkcs11_label_var(), "praetore-evidence"),
            (PKCS11_MODULE_VAR, "/nonexistent/module.so"),
            (PKCS11_TOKEN_LABEL_VAR, "praetore"),
            (PKCS11_PIN_FILE_VAR, pin.as_str()),
        ];
        assert_eq!(
            load_signer(role, true, &env_of(&without_pin))
                .err()
                .unwrap(),
            SigningKeyError::Pkcs11Config(role.pkcs11_public_key_var())
        );
        let public_key = hex::encode(expected_public_key());
        let public = dir.write("public.hex", format!("{public_key}\n").as_bytes(), 0o644);
        let bad_public = dir.write("bad-public.hex", b"not hex\n", 0o644);
        let mut with_bad_pin = without_pin.to_vec();
        with_bad_pin.push((role.pkcs11_public_key_var(), bad_public.as_str()));
        assert_eq!(
            load_signer(role, true, &env_of(&with_bad_pin))
                .err()
                .unwrap(),
            SigningKeyError::InvalidHex(role.pkcs11_public_key_var())
        );
        let readable_pin = dir.write("pin", b"1234\n", 0o644);
        let env = env_of(&[
            (role.pkcs11_label_var(), "praetore-evidence"),
            (PKCS11_MODULE_VAR, "/nonexistent/module.so"),
            (PKCS11_TOKEN_LABEL_VAR, "praetore"),
            (PKCS11_PIN_FILE_VAR, &readable_pin),
            (role.pkcs11_public_key_var(), &public),
        ]);
        let error = load_signer(role, true, &env).err().unwrap();
        assert!(matches!(
            error,
            SigningKeyError::SecretFile {
                var: PKCS11_PIN_FILE_VAR,
                ..
            }
        ));
        let mut complete = without_pin.to_vec();
        complete.push((role.pkcs11_public_key_var(), public.as_str()));
        let error = load_signer(role, true, &env_of(&complete)).err().unwrap();
        assert!(matches!(error, SigningKeyError::Pkcs11(_)));
        assert!(!error.to_string().contains("1234"));
    }

    /// End to end with SoftHSM2: the service's variables, a PIN file and a
    /// key generated in a throwaway token. Ignored by default; run alone
    /// (it sets `SOFTHSM2_CONF`):
    /// `PRAETORE_TEST_PKCS11_MODULE=... cargo test -p praetore-gateway-service
    /// --features pkcs11 --lib -- --ignored --exact
    /// signing_keys::tests::pkcs11_signer_loads_from_softhsm`.
    #[test]
    #[cfg(feature = "pkcs11")]
    #[ignore = "requires SoftHSM2 (PRAETORE_TEST_PKCS11_MODULE); run alone"]
    fn pkcs11_signer_loads_from_softhsm() {
        use praetore_signer_pkcs11::softhsm_testing::{TestKey, create_token, write_config};
        let module = std::env::var("PRAETORE_TEST_PKCS11_MODULE")
            .expect("PRAETORE_TEST_PKCS11_MODULE is required");
        let dir = TempDir::new();
        let conf = write_config(&dir.0);
        // SAFETY: this test is run alone (see above), so no other thread
        // reads the environment concurrently.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
        create_token(
            Path::new(&module),
            "praetore-service",
            "so-pin-4821",
            "user-pin-5530",
            &[
                TestKey {
                    label: "evidence",
                    extractable: false,
                },
                TestKey {
                    label: "execution",
                    extractable: false,
                },
            ],
        );
        let pin = dir.write("pin", b"user-pin-5530\n", 0o600);
        // The operator records each public key when the key is generated.
        let public_key_of = |label: &str| {
            let signer =
                praetore_signer_pkcs11::Pkcs11Signer::open(&praetore_signer_pkcs11::Pkcs11Config {
                    module: module.clone().into(),
                    token_label: "praetore-service".into(),
                    key_label: label.into(),
                    user_pin: cryptoki_pin("user-pin-5530"),
                    algorithm: SignatureAlgorithm::Ed25519,
                    expected_public_key: None,
                })
                .unwrap();
            hex::encode(signer.verifying_key().as_bytes())
        };
        let evidence_pin = dir.write("evidence.pub", public_key_of("evidence").as_bytes(), 0o644);
        let execution_pin = dir.write(
            "execution.pub",
            public_key_of("execution").as_bytes(),
            0o644,
        );
        let mut pairs = vec![
            (KeyRole::EvidenceAttester.pkcs11_label_var(), "evidence"),
            (KeyRole::ExecutionAttester.pkcs11_label_var(), "execution"),
            (EVIDENCE_ALGORITHM_VAR, "ed25519-sha256-envelope"),
            (PKCS11_MODULE_VAR, module.as_str()),
            (PKCS11_TOKEN_LABEL_VAR, "praetore-service"),
            (PKCS11_PIN_FILE_VAR, pin.as_str()),
            (
                KeyRole::EvidenceAttester.pkcs11_public_key_var(),
                evidence_pin.as_str(),
            ),
            (
                KeyRole::ExecutionAttester.pkcs11_public_key_var(),
                execution_pin.as_str(),
            ),
        ];
        let (evidence, execution) = load_signers(true, &env_of(&pairs)).unwrap();
        // A pin naming the other key (as after a key pair was regenerated
        // under the label) is refused at startup.
        pairs[6].1 = execution_pin.as_str();
        assert_eq!(
            load_signer(KeyRole::EvidenceAttester, true, &env_of(&pairs))
                .err()
                .unwrap(),
            SigningKeyError::Pkcs11(
                praetore_signer_pkcs11::Pkcs11SignerError::UnexpectedPublicKey.to_string()
            )
        );
        // The same token key for both roles is refused.
        pairs[6].1 = evidence_pin.as_str();
        pairs[1].1 = "evidence";
        pairs[7].1 = evidence_pin.as_str();
        assert_eq!(
            load_signers(true, &env_of(&pairs)).err().unwrap(),
            SigningKeyError::SameKeyForBothRoles
        );
        assert_eq!(evidence.source, KeySource::Pkcs11);
        assert_eq!(
            evidence.signer.algorithm(),
            SignatureAlgorithm::Ed25519Sha256Envelope
        );
        assert_eq!(execution.signer.algorithm(), SignatureAlgorithm::Ed25519);
        assert_ne!(
            evidence.signer.verifying_key(),
            execution.signer.verifying_key()
        );
        assert!(execution.execution_key_id().starts_with("pkcs11-"));
        for loaded in [&evidence, &execution] {
            let signature =
                praetore_core::signer::sign_exact(loaded.signer.as_ref(), b"message").unwrap();
            loaded
                .signer
                .verifying_key()
                .verify_domain_message(b"", b"message", &signature)
                .unwrap();
        }
        println!(
            "gateway-service pkcs11: evidence key_id={} algorithm={}; execution key_id={}",
            evidence.signer.key_id(),
            evidence.signer.algorithm(),
            execution.execution_key_id()
        );
    }
}
