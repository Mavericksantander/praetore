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
    let error = |reason| SigningKeyError::SecretFile { var, reason };
    let metadata = fs::metadata(path).map_err(|_| error("cannot be read"))?;
    if !metadata.is_file() {
        return Err(error("is not a regular file"));
    }
    if metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(error("is larger than 256 bytes"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(error(
                "is accessible by group or others; set its mode to 0600 or 0400",
            ));
        }
    }
    let contents = Zeroizing::new(fs::read(path).map_err(|_| error("cannot be read"))?);
    if contents.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(error("is larger than 256 bytes"));
    }
    Ok(contents)
}

fn decode_key_hex(text: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 {
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (index, pair) in text.chunks_exact(2).enumerate() {
        let high = lower_hex_value(pair[0])?;
        let low = lower_hex_value(pair[1])?;
        key[index] = (high << 4) | low;
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

#[cfg(feature = "pkcs11")]
fn pkcs11_signer(
    _role: KeyRole,
    label: &str,
    algorithm: SignatureAlgorithm,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Arc<dyn Signer>, SigningKeyError> {
    let required = |var: &'static str| env(var).ok_or(SigningKeyError::Pkcs11Config(var));
    let module = required(PKCS11_MODULE_VAR)?;
    let token_label = required(PKCS11_TOKEN_LABEL_VAR)?;
    let pin_path = required(PKCS11_PIN_FILE_VAR)?;
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
        expected_public_key: None,
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
    fn pkcs11_keys_need_module_token_and_pin_file() {
        let role = KeyRole::EvidenceAttester;
        let env = env_of(&[(role.pkcs11_label_var(), "praetore-evidence")]);
        assert_eq!(
            load_signer(role, true, &env).err().unwrap(),
            SigningKeyError::Pkcs11Config(PKCS11_MODULE_VAR)
        );
        let dir = TempDir::new();
        let pin = dir.write("pin", b"1234\n", 0o644);
        let env = env_of(&[
            (role.pkcs11_label_var(), "praetore-evidence"),
            (PKCS11_MODULE_VAR, "/nonexistent/module.so"),
            (PKCS11_TOKEN_LABEL_VAR, "praetore"),
            (PKCS11_PIN_FILE_VAR, &pin),
        ]);
        let error = load_signer(role, true, &env).err().unwrap();
        assert!(matches!(
            error,
            SigningKeyError::SecretFile {
                var: PKCS11_PIN_FILE_VAR,
                ..
            }
        ));
        let pin = dir.write("pin-private", b"1234\n", 0o600);
        let env = env_of(&[
            (role.pkcs11_label_var(), "praetore-evidence"),
            (PKCS11_MODULE_VAR, "/nonexistent/module.so"),
            (PKCS11_TOKEN_LABEL_VAR, "praetore"),
            (PKCS11_PIN_FILE_VAR, &pin),
        ]);
        let error = load_signer(role, true, &env).err().unwrap();
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
        let env = env_of(&[
            (KeyRole::EvidenceAttester.pkcs11_label_var(), "evidence"),
            (KeyRole::ExecutionAttester.pkcs11_label_var(), "execution"),
            (EVIDENCE_ALGORITHM_VAR, "ed25519-sha256-envelope"),
            (PKCS11_MODULE_VAR, &module),
            (PKCS11_TOKEN_LABEL_VAR, "praetore-service"),
            (PKCS11_PIN_FILE_VAR, &pin),
        ]);
        let evidence = load_signer(KeyRole::EvidenceAttester, true, &env).unwrap();
        let execution = load_signer(KeyRole::ExecutionAttester, true, &env).unwrap();
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
