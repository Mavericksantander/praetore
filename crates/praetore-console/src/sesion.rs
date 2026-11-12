//! Local session: a key on disk that the browser stores as an HttpOnly cookie.
//! The console never writes that key into the page.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use subtle::ConstantTimeEq;

pub const COOKIE_NAME: &str = "praetore_consola";

pub struct LocalSession {
    secret: [u8; 32],
}

impl std::fmt::Debug for LocalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalSession")
    }
}

impl LocalSession {
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Opens an existing 0600 file of 32 bytes, or creates one.
    pub fn load_or_create(path: &Path) -> Result<Self, SessionError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => read_existing(path, &metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => create(path),
            Err(_) => Err(SessionError::Io),
        }
    }

    pub fn cookie_header(&self) -> String {
        format!(
            "{COOKIE_NAME}={}; HttpOnly; SameSite=Strict; Path=/",
            self.cookie_value()
        )
    }

    pub fn cookie_value(&self) -> String {
        hex::encode(self.secret)
    }

    pub fn accepts(&self, cookie_header: Option<&str>) -> bool {
        let Some(header) = cookie_header else {
            return false;
        };
        if header.len() > 4096 {
            return false;
        }
        for part in header.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name.trim() != COOKIE_NAME {
                continue;
            }
            let value = value.trim();
            if value.len() != 64 {
                return false;
            }
            let Ok(bytes) = hex::decode(value) else {
                return false;
            };
            let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
                return false;
            };
            return bool::from(bytes.as_slice().ct_eq(self.secret.as_slice()));
        }
        false
    }
}

#[derive(Debug)]
pub enum SessionError {
    Io,
    Permissions,
    Unsupported,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => f.write_str("no se pudo leer o crear la sesión local"),
            Self::Permissions => {
                f.write_str("la sesión local debe ser un archivo regular con permisos 0600")
            }
            Self::Unsupported => {
                f.write_str("la sesión local de esta consola está hecha para Linux")
            }
        }
    }
}

impl std::error::Error for SessionError {}

fn read_existing(path: &Path, metadata: &fs::Metadata) -> Result<LocalSession, SessionError> {
    if !metadata.file_type().is_file() || !mode_is_owner_only(metadata) || metadata.len() != 32 {
        return Err(SessionError::Permissions);
    }
    let mut file = fs::File::open(path).map_err(|_| SessionError::Io)?;
    let mut secret = [0u8; 32];
    file.read_exact(&mut secret).map_err(|_| SessionError::Io)?;
    Ok(LocalSession { secret })
}

fn create(path: &Path) -> Result<LocalSession, SessionError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|_| SessionError::Io)?;
    }
    let secret = random_bytes()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| SessionError::Io)?;
        file.write_all(&secret).map_err(|_| SessionError::Io)?;
        file.sync_all().map_err(|_| SessionError::Io)?;
        let metadata = file.metadata().map_err(|_| SessionError::Io)?;
        if !mode_is_owner_only(&metadata) {
            return Err(SessionError::Permissions);
        }
        Ok(LocalSession { secret })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, secret);
        Err(SessionError::Unsupported)
    }
}

fn random_bytes() -> Result<[u8; 32], SessionError> {
    let mut secret = [0u8; 32];
    let mut source = fs::File::open("/dev/urandom").map_err(|_| SessionError::Io)?;
    source
        .read_exact(&mut secret)
        .map_err(|_| SessionError::Io)?;
    Ok(secret)
}

fn mode_is_owner_only(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777 == 0o600
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_new_session_file_is_owner_only_and_reopens() {
        let dir =
            std::env::temp_dir().join(format!("praetore-consola-sesion-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sesion");
        let first = LocalSession::load_or_create(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let header = format!("{COOKIE_NAME}={}", first.cookie_value());
        let second = LocalSession::load_or_create(&path).unwrap();
        assert!(second.accepts(Some(&header)));
        assert!(!second.accepts(None));
        assert!(!second.accepts(Some(&format!("{COOKIE_NAME}={}", "00".repeat(32)))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_world_readable_session_file_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "praetore-consola-permisos-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sesion");
        fs::write(&path, [9u8; 32]).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(matches!(
            LocalSession::load_or_create(&path),
            Err(SessionError::Permissions)
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
