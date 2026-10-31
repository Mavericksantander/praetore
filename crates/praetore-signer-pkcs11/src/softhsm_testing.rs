//! Test support only (feature `softhsm-testing`): creates a throwaway
//! SoftHSM2 token with Ed25519 keys. Never enable it in a deployment.
//!
//! The caller points `SOFTHSM2_CONF` at a configuration whose token
//! directory is temporary before the module is first loaded.

use cryptoki::{
    mechanism::Mechanism, object::Attribute, session::UserType, slot::Slot, types::AuthPin,
};
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, Once},
};

const EDWARDS25519_NAME_DER: [u8; 14] = [
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
];

/// A key pair to generate: its label and whether the private key may leave
/// the token (`true` only to test that such keys are refused).
pub struct TestKey<'a> {
    pub label: &'a str,
    pub extractable: bool,
}

/// Writes a SoftHSM2 configuration that keeps tokens under `root/tokens`
/// and returns its path.
pub fn write_config(root: &Path) -> PathBuf {
    let tokens = root.join("tokens");
    std::fs::create_dir_all(&tokens).expect("token directory");
    let conf = root.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
            tokens.display()
        ),
    )
    .expect("softhsm2.conf");
    conf
}

/// Initializes a free slot as `token_label` and generates `keys` in it.
/// Panics on any failure (test support).
pub fn create_token(
    module: &Path,
    token_label: &str,
    so_pin: &str,
    user_pin: &str,
    keys: &[TestKey<'_>],
) {
    let pkcs11 = crate::load_module(module).expect("load SoftHSM2");
    let free = pkcs11
        .get_all_slots()
        .expect("slots")
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .is_ok_and(|info| !info.token_initialized())
        })
        .expect("SoftHSM2 offers a free slot");
    let so_pin = AuthPin::new(so_pin.into());
    pkcs11
        .init_token(free, &so_pin, token_label)
        .expect("C_InitToken");
    // SoftHSM2 renumbers the slot of a newly initialized token.
    let slot: Slot = pkcs11
        .get_slots_with_initialized_token()
        .expect("slots")
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .is_ok_and(|info| info.label().trim_end() == token_label)
        })
        .expect("initialized token");
    let session = pkcs11.open_rw_session(slot).expect("C_OpenSession");
    session
        .login(UserType::So, Some(&so_pin))
        .expect("SO login");
    session
        .init_pin(&AuthPin::new(user_pin.into()))
        .expect("C_InitPIN");
    session.logout().expect("C_Logout");
    session
        .login(UserType::User, Some(&AuthPin::new(user_pin.into())))
        .expect("user login");
    for key in keys {
        session
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::EcParams(EDWARDS25519_NAME_DER.to_vec()),
                    Attribute::Label(key.label.as_bytes().to_vec()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sign(true),
                    Attribute::Sensitive(!key.extractable),
                    Attribute::Extractable(key.extractable),
                    Attribute::Label(key.label.as_bytes().to_vec()),
                ],
            )
            .expect("C_GenerateKeyPair");
    }
}

/// Logs in as the user in a new session of `token_label`, for test set-up.
fn user_session(module: &Path, token_label: &str, user_pin: &str) -> cryptoki::session::Session {
    let pkcs11 = crate::load_module(module).expect("load SoftHSM2");
    let slot = pkcs11
        .get_slots_with_initialized_token()
        .expect("slots")
        .into_iter()
        .find(|slot| {
            pkcs11
                .get_token_info(*slot)
                .is_ok_and(|info| info.label().trim_end() == token_label)
        })
        .expect("token");
    let session = pkcs11.open_rw_session(slot).expect("C_OpenSession");
    match session.login(UserType::User, Some(&AuthPin::new(user_pin.into()))) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {
        }
        Err(error) => panic!("user login: {error}"),
    }
    session
}

/// Imports an Ed25519 key pair in clear (`C_CreateObject` with `CKA_VALUE`),
/// marked sensitive and not extractable. Its `CKA_NEVER_EXTRACTABLE` and
/// `CKA_ALWAYS_SENSITIVE` are false: the material existed outside the token.
pub fn import_key(module: &Path, token_label: &str, user_pin: &str, label: &str, secret: [u8; 32]) {
    let public = praetore_core::LocalSigner::from_secret_bytes(&secret)
        .public_key()
        .expect("public key")
        .as_bytes();
    let mut point = vec![0x04, 0x20];
    point.extend_from_slice(&public);
    let session = user_session(module, token_label, user_pin);
    session
        .create_object(&[
            Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::EcParams(EDWARDS25519_NAME_DER.to_vec()),
            Attribute::Value(secret.to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .expect("import private key");
    session
        .create_object(&[
            Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::EcParams(EDWARDS25519_NAME_DER.to_vec()),
            Attribute::EcPoint(point),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .expect("import public key");
}

/// Marks a key generated as extractable and not sensitive as not
/// extractable and sensitive, as after exporting it. Its
/// `CKA_NEVER_EXTRACTABLE` and `CKA_ALWAYS_SENSITIVE` stay false.
pub fn lock_exported_key(module: &Path, token_label: &str, user_pin: &str, label: &str) {
    let session = user_session(module, token_label, user_pin);
    let keys = session
        .find_objects(&[
            Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .expect("find key");
    for key in keys {
        session
            .update_attributes(
                key,
                &[Attribute::Sensitive(true), Attribute::Extractable(false)],
            )
            .expect("C_SetAttributeValue");
    }
}

/// Logs the whole process out of the token (PKCS#11 login is per process),
/// as an HSM session timeout or another component would.
pub fn logout_process(module: &Path, token_label: &str, user_pin: &str) {
    let session = user_session(module, token_label, user_pin);
    session.logout().expect("C_Logout");
}

/// Removes `path` when the process exits: the SoftHSM2 token directory must
/// outlive every test of the binary, so a drop guard cannot remove it.
pub fn remove_at_exit(path: PathBuf) {
    static PATHS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    static REGISTER: Once = Once::new();
    extern "C" fn cleanup() {
        if let Ok(paths) = PATHS.lock() {
            for path in paths.iter() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
    PATHS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(path);
    REGISTER.call_once(|| {
        // SAFETY: `cleanup` is a plain `extern "C"` function with no
        // arguments, as `atexit` requires.
        unsafe {
            libc::atexit(cleanup);
        }
    });
}
