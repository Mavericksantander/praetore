//! Local session: a secret held only in this process that the browser
//! stores as an HttpOnly cookie, and the single-use opening link that hands
//! it out. The secret is new on every start, so a cookie from an earlier run
//! stops working, and nothing is written to disk.

use std::{
    fs,
    io::Read,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub const COOKIE_NAME: &str = "praetore_consola";

/// The longest an opening link is valid.
pub const MAX_OPENING_TTL: Duration = Duration::from_secs(5 * 60);

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

    /// A fresh secret for this run only.
    pub fn random() -> Result<Self, SessionError> {
        Ok(Self {
            secret: random_bytes()?,
        })
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
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => f.write_str("no se pudo crear la sesión local"),
        }
    }
}

impl std::error::Error for SessionError {}

pub(crate) fn random_bytes() -> Result<[u8; 32], SessionError> {
    let mut secret = [0u8; 32];
    let mut source = fs::File::open("/dev/urandom").map_err(|_| SessionError::Io)?;
    source
        .read_exact(&mut secret)
        .map_err(|_| SessionError::Io)?;
    Ok(secret)
}

/// The opening link's code: single use, valid for at most five minutes.
pub struct Opener {
    ttl: Duration,
    state: Mutex<OpenerState>,
}

#[derive(Default)]
struct OpenerState {
    current: Option<(String, Instant)>,
}

impl Opener {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl: ttl.min(MAX_OPENING_TTL),
            state: Mutex::default(),
        }
    }

    /// A new code; any earlier one stops working.
    pub fn issue(&self) -> Option<String> {
        let code = crate::bandeja::random_code()?;
        let mut state = self.state.lock().ok()?;
        state.current = Some((code.clone(), Instant::now()));
        Some(code)
    }

    /// Consumes the code: true at most once, and only before it expires.
    pub fn redeem(&self, offered: &str) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some((code, issued)) = state.current.as_ref() else {
            return false;
        };
        let matches =
            code.len() == offered.len() && bool::from(code.as_bytes().ct_eq(offered.as_bytes()));
        if !matches {
            return false;
        }
        let fresh = issued.elapsed() < self.ttl;
        state.current = None;
        fresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_run_has_a_new_cookie() {
        let first = LocalSession::random().unwrap();
        let second = LocalSession::random().unwrap();
        let header = format!("{COOKIE_NAME}={}", first.cookie_value());
        assert!(first.accepts(Some(&header)));
        assert!(!second.accepts(Some(&header)));
        assert!(!second.accepts(None));
    }

    #[test]
    fn an_opening_code_works_once_and_only_before_it_expires() {
        let opener = Opener::new(Duration::from_secs(60));
        let code = opener.issue().unwrap();
        assert!(!opener.redeem("otro"));
        assert!(opener.redeem(&code));
        assert!(!opener.redeem(&code));

        let expired = Opener::new(Duration::ZERO);
        let code = expired.issue().unwrap();
        assert!(!expired.redeem(&code));

        // The TTL is capped at five minutes.
        assert_eq!(Opener::new(Duration::from_secs(3600)).ttl, MAX_OPENING_TTL);

        // A new code replaces the earlier one.
        let opener = Opener::new(Duration::from_secs(60));
        let old = opener.issue().unwrap();
        let new = opener.issue().unwrap();
        assert!(!opener.redeem(&old));
        assert!(opener.redeem(&new));
    }
}
