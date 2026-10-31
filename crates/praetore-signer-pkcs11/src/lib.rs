//! A [`praetore_core::Signer`] backed by an Ed25519 key in a PKCS#11 token
//! (an HSM, or SoftHSM2 for development and CI). SAF-11, decision 2.
//!
//! The private key never leaves the token: the signer only asks the token to
//! sign (`CKM_EDDSA`, pure Ed25519, no prehash) and reads the public key once
//! when it is opened. Opening fails closed if:
//!
//! * the module cannot be loaded, the token is not found, or login fails;
//! * there is not exactly one private key and one public key with the label;
//! * the key is not Ed25519 (`CKK_EC_EDWARDS` on `edwards25519`);
//! * the private key is extractable or not sensitive;
//! * the public key differs from the pinned one (when one is configured);
//! * a test signature made by the private key does not verify under the
//!   public key object (a mismatched pair).
//!
//! Errors never contain the PIN or key material.

pub use cryptoki::types::AuthPin;

#[cfg(feature = "softhsm-testing")]
pub mod softhsm_testing;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11},
    error::{Error as CryptokiError, RvError},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
};
use praetore_core::{
    SignatureAlgorithm, Signer, SignerError, VerifiedPublicKey, signer::attester_key_id,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
use thiserror::Error;

/// DER of the `id-Ed25519` OID (RFC 8410), one accepted `CKA_EC_PARAMS`.
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER PrintableString `edwards25519`, the other accepted `CKA_EC_PARAMS`
/// (PKCS#11 3.0 curve name; SoftHSM2 uses it).
const EDWARDS25519_NAME_DER: &[u8] = &[
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
];
const SELF_TEST_MESSAGE: &[u8] = b"PRAETORE_PKCS11_SELF_TEST_V1\0";

/// Where the key is and how to unlock it.
pub struct Pkcs11Config {
    /// Path of the PKCS#11 module (`.so`/`.dylib`).
    pub module: PathBuf,
    /// `CKA_LABEL` of the token (exact match, without padding).
    pub token_label: String,
    /// `CKA_LABEL` of the key pair (exact match).
    pub key_label: String,
    /// User PIN. Kept in a zeroizing secret type.
    pub user_pin: AuthPin,
    /// Algorithm used for evidence attester signatures.
    pub algorithm: SignatureAlgorithm,
    /// When set, the token's public key must be exactly this one.
    pub expected_public_key: Option<VerifiedPublicKey>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module", &self.module)
            .field("token_label", &self.token_label)
            .field("key_label", &self.key_label)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Why a PKCS#11 signer could not be opened. Fixed messages plus, at most,
/// the PKCS#11 return code; never the PIN or key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Pkcs11SignerError {
    #[error("PKCS#11 module could not be loaded")]
    ModuleLoad,
    #[error("PKCS#11 call {function} failed ({code})")]
    Call {
        function: &'static str,
        code: String,
    },
    #[error("no PKCS#11 token with the configured label")]
    TokenNotFound,
    #[error("more than one PKCS#11 token has the configured label")]
    TokenAmbiguous,
    #[error("PKCS#11 login failed ({code})")]
    Login { code: String },
    #[error("expected exactly one private and one public key with the configured label")]
    KeyNotFound,
    #[error("the PKCS#11 key is not an Ed25519 key")]
    NotEd25519,
    #[error("the PKCS#11 private key is extractable or not sensitive")]
    KeyExportable,
    #[error("the PKCS#11 public key does not match the pinned public key")]
    UnexpectedPublicKey,
    #[error("the PKCS#11 private key does not match its public key object")]
    KeyPairMismatch,
}

/// An Ed25519 key held by a PKCS#11 token.
pub struct Pkcs11Signer {
    // Field order: the session closes before the module handle is dropped.
    session: Mutex<Session>,
    private_key: ObjectHandle,
    verifying_key: VerifiedPublicKey,
    algorithm: SignatureAlgorithm,
    _module: Pkcs11,
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("key_id", &attester_key_id(&self.verifying_key))
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

fn call_error(error: CryptokiError) -> Pkcs11SignerError {
    match error {
        CryptokiError::LibraryLoading(_) => Pkcs11SignerError::ModuleLoad,
        CryptokiError::Pkcs11(rv, function) => Pkcs11SignerError::Call {
            function: function_name(function),
            code: format!("{rv:?}"),
        },
        other => Pkcs11SignerError::Call {
            function: "binding",
            code: match other {
                CryptokiError::NotSupported => "NotSupported",
                CryptokiError::NullFunctionPointer => "NullFunctionPointer",
                CryptokiError::MissingSymbol(_) => "MissingSymbol",
                _ => "InvalidValue",
            }
            .into(),
        },
    }
}

fn function_name(function: Function) -> &'static str {
    match function {
        Function::Initialize => "C_Initialize",
        Function::GetSlotList => "C_GetSlotList",
        Function::GetTokenInfo => "C_GetTokenInfo",
        Function::OpenSession => "C_OpenSession",
        Function::Login => "C_Login",
        Function::FindObjectsInit | Function::FindObjects | Function::FindObjectsFinal => {
            "C_FindObjects"
        }
        Function::GetAttributeValue => "C_GetAttributeValue",
        Function::SignInit | Function::Sign => "C_Sign",
        _ => "PKCS#11",
    }
}

/// Transient token conditions; everything else is a refusal.
fn is_transient(rv: RvError) -> bool {
    matches!(
        rv,
        RvError::DeviceError
            | RvError::DeviceMemory
            | RvError::DeviceRemoved
            | RvError::SessionClosed
            | RvError::SessionHandleInvalid
            | RvError::TokenNotPresent
            | RvError::FunctionFailed
            | RvError::HostMemory
            | RvError::UserNotLoggedIn
            | RvError::OperationActive
            | RvError::SessionCount
    )
}

/// Parses `CKA_EC_PARAMS`: only Ed25519 is accepted.
pub fn is_ed25519_params(params: &[u8]) -> bool {
    params == ED25519_OID_DER || params == EDWARDS25519_NAME_DER
}

/// Parses `CKA_EC_POINT` of an Ed25519 key: the DER OCTET STRING
/// `04 20 || key` (PKCS#11 3.0) or, from older tokens, the 32 raw bytes.
pub fn ed25519_point(point: &[u8]) -> Option<[u8; 32]> {
    match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest.try_into().ok(),
        raw if raw.len() == 32 => raw.try_into().ok(),
        _ => None,
    }
}

impl Pkcs11Signer {
    /// Loads the module, logs in to the token and checks the key pair. See
    /// the crate documentation for every check.
    pub fn open(config: &Pkcs11Config) -> Result<Self, Pkcs11SignerError> {
        let module = load_module(&config.module)?;
        let slot = find_token(&module, &config.token_label)?;
        let session = module.open_ro_session(slot).map_err(call_error)?;
        // PKCS#11 login state is shared by every session of this process on
        // the token: if another signer is already logged in, the token does
        // not check this PIN again.
        match session.login(UserType::User, Some(&config.user_pin)) {
            Ok(()) | Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(CryptokiError::Pkcs11(rv, _)) => {
                return Err(Pkcs11SignerError::Login {
                    code: format!("{rv:?}"),
                });
            }
            Err(error) => return Err(call_error(error)),
        }

        let private_key = single_key(&session, ObjectClass::PRIVATE_KEY, &config.key_label)?;
        let public_key = single_key(&session, ObjectClass::PUBLIC_KEY, &config.key_label)?;
        check_private_key(&session, private_key)?;
        let verifying_key = read_public_key(&session, public_key)?;
        if config
            .expected_public_key
            .as_ref()
            .is_some_and(|expected| expected != &verifying_key)
        {
            return Err(Pkcs11SignerError::UnexpectedPublicKey);
        }

        let signer = Self {
            session: Mutex::new(session),
            private_key,
            verifying_key,
            algorithm: config.algorithm,
            _module: module,
        };
        praetore_core::signer::sign_exact(&signer, SELF_TEST_MESSAGE).map_err(
            |error| match error {
                SignerError::InvalidSignature => Pkcs11SignerError::KeyPairMismatch,
                _ => Pkcs11SignerError::Call {
                    function: "C_Sign",
                    code: "self-test failed".into(),
                },
            },
        )?;
        Ok(signer)
    }
}

/// Loads and initializes a PKCS#11 module once per process and keeps it
/// loaded: PKCS#11 expects one `C_Initialize` per process, and unloading a
/// module invalidates every session opened through it. Signers for several
/// keys of the same module share it.
pub fn load_module(path: &Path) -> Result<Pkcs11, Pkcs11SignerError> {
    static MODULES: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();
    let path = path
        .canonicalize()
        .map_err(|_| Pkcs11SignerError::ModuleLoad)?;
    let mut modules = MODULES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Pkcs11SignerError::ModuleLoad)?;
    if let Some(module) = modules.get(&path) {
        return Ok(module.clone());
    }
    let module = Pkcs11::new(&path).map_err(call_error)?;
    match module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        // Initialized by other code in this process.
        Ok(()) | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(error) => return Err(call_error(error)),
    }
    modules.insert(path, module.clone());
    Ok(module)
}

fn find_token(module: &Pkcs11, label: &str) -> Result<cryptoki::slot::Slot, Pkcs11SignerError> {
    let mut found = None;
    for slot in module
        .get_slots_with_initialized_token()
        .map_err(call_error)?
    {
        let info = module.get_token_info(slot).map_err(call_error)?;
        if info.label().trim_end() == label {
            if found.is_some() {
                return Err(Pkcs11SignerError::TokenAmbiguous);
            }
            found = Some(slot);
        }
    }
    found.ok_or(Pkcs11SignerError::TokenNotFound)
}

fn single_key(
    session: &Session,
    class: ObjectClass,
    label: &str,
) -> Result<ObjectHandle, Pkcs11SignerError> {
    let objects = session
        .find_objects(&[
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .map_err(call_error)?;
    match objects.as_slice() {
        [object] => Ok(*object),
        _ => Err(Pkcs11SignerError::KeyNotFound),
    }
}

fn check_private_key(session: &Session, key: ObjectHandle) -> Result<(), Pkcs11SignerError> {
    let attributes = session
        .get_attributes(
            key,
            &[
                AttributeType::KeyType,
                AttributeType::EcParams,
                AttributeType::Sign,
                AttributeType::Sensitive,
                AttributeType::Extractable,
            ],
        )
        .map_err(call_error)?;
    let (mut key_type, mut params, mut sign, mut sensitive, mut extractable) =
        (None, None, None, None, None);
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::EcParams(value) => params = Some(value),
            Attribute::Sign(value) => sign = Some(value),
            Attribute::Sensitive(value) => sensitive = Some(value),
            Attribute::Extractable(value) => extractable = Some(value),
            _ => {}
        }
    }
    if key_type != Some(KeyType::EC_EDWARDS)
        || !params.as_deref().is_some_and(is_ed25519_params)
        || sign != Some(true)
    {
        return Err(Pkcs11SignerError::NotEd25519);
    }
    if sensitive != Some(true) || extractable != Some(false) {
        return Err(Pkcs11SignerError::KeyExportable);
    }
    Ok(())
}

fn read_public_key(
    session: &Session,
    key: ObjectHandle,
) -> Result<VerifiedPublicKey, Pkcs11SignerError> {
    let attributes = session
        .get_attributes(
            key,
            &[
                AttributeType::KeyType,
                AttributeType::EcParams,
                AttributeType::EcPoint,
            ],
        )
        .map_err(call_error)?;
    let (mut key_type, mut params, mut point) = (None, None, None);
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::EcParams(value) => params = Some(value),
            Attribute::EcPoint(value) => point = Some(value),
            _ => {}
        }
    }
    if key_type != Some(KeyType::EC_EDWARDS) || !params.as_deref().is_some_and(is_ed25519_params) {
        return Err(Pkcs11SignerError::NotEd25519);
    }
    let bytes = point
        .as_deref()
        .and_then(ed25519_point)
        .ok_or(Pkcs11SignerError::NotEd25519)?;
    VerifiedPublicKey::from_bytes(&bytes).map_err(|_| Pkcs11SignerError::NotEd25519)
}

impl Signer for Pkcs11Signer {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn verifying_key(&self) -> &VerifiedPublicKey {
        &self.verifying_key
    }

    fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let session = self.session.lock().map_err(|_| SignerError::Unavailable)?;
        session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                self.private_key,
                message,
            )
            .map_err(|error| match error {
                CryptokiError::Pkcs11(rv, _) if is_transient(rv) => SignerError::Unavailable,
                CryptokiError::Pkcs11(RvError::DataLenRange, _) => SignerError::MessageTooLarge,
                _ => SignerError::Rejected,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ed25519_curve_parameters_are_accepted() {
        assert!(is_ed25519_params(ED25519_OID_DER));
        assert!(is_ed25519_params(EDWARDS25519_NAME_DER));
        // id-Ed448, P-256 and a truncated OID.
        assert!(!is_ed25519_params(&[0x06, 0x03, 0x2b, 0x65, 0x71]));
        assert!(!is_ed25519_params(&[
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        ]));
        assert!(!is_ed25519_params(&[0x06, 0x03, 0x2b, 0x65]));
        assert!(!is_ed25519_params(&[]));
    }

    #[test]
    fn ec_points_are_parsed_strictly() {
        let key = [7u8; 32];
        let mut der = vec![0x04, 0x20];
        der.extend_from_slice(&key);
        assert_eq!(ed25519_point(&der), Some(key));
        assert_eq!(ed25519_point(&key), Some(key));
        assert_eq!(ed25519_point(&der[..33]), None);
        let mut long = der.clone();
        long.push(0);
        assert_eq!(ed25519_point(&long), None);
        assert_eq!(ed25519_point(&[0x04, 0x21, 0, 0]), None);
        assert_eq!(ed25519_point(&[]), None);
    }

    #[test]
    fn transient_and_permanent_token_errors_are_told_apart() {
        assert!(is_transient(RvError::DeviceRemoved));
        assert!(is_transient(RvError::SessionHandleInvalid));
        assert!(!is_transient(RvError::KeyHandleInvalid));
        assert!(!is_transient(RvError::MechanismInvalid));
        assert!(!is_transient(RvError::PinIncorrect));
    }

    #[test]
    fn a_missing_module_fails_closed_without_details() {
        let config = Pkcs11Config {
            module: "/nonexistent/praetore-no-such-module.so".into(),
            token_label: "praetore".into(),
            key_label: "evidence".into(),
            user_pin: AuthPin::new("123456-not-logged".into()),
            algorithm: SignatureAlgorithm::Ed25519,
            expected_public_key: None,
        };
        let error = Pkcs11Signer::open(&config).unwrap_err();
        assert_eq!(error, Pkcs11SignerError::ModuleLoad);
        assert_eq!(
            load_module(Path::new("/nonexistent/praetore-no-such-module.so")).unwrap_err(),
            Pkcs11SignerError::ModuleLoad
        );
        assert!(!format!("{config:?}").contains("123456-not-logged"));
    }
}
