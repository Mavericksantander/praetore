//! Test support only (feature `softhsm-testing`): creates a throwaway
//! SoftHSM2 token with Ed25519 keys. Never enable it in a deployment.
//!
//! The caller points `SOFTHSM2_CONF` at a configuration whose token
//! directory is temporary before the module is first loaded.

use cryptoki::{
    mechanism::Mechanism, object::Attribute, session::UserType, slot::Slot, types::AuthPin,
};
use std::path::{Path, PathBuf};

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
