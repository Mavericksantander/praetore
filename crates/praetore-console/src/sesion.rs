//! Local session: a bearer token minted in this process and handed out once
//! by the single-use opening link. The browser keeps it in `sessionStorage`,
//! scoped to the opening tab's origin, and sends it as `Authorization:
//! Bearer`. No ambient session cookie is used. A request without a live token
//! is refused. Tokens expire, and the opening code is single use.

use std::{
    fs,
    io::Read,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

/// A minted session token is valid for at most this long; an older one is
/// refused (the session expires). Each opening mints a fresh token, so in
/// practice the session also rotates.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// The longest an opening link is valid.
pub const MAX_OPENING_TTL: Duration = Duration::from_secs(5 * 60);

/// At most this many live tokens at once; the oldest drops first. Bounds
/// memory and lets a couple of re-opens coexist without unbounded growth.
const MAX_LIVE_TOKENS: usize = 8;

struct Live {
    value: [u8; 32],
    issued: Instant,
}

pub struct LocalSession {
    ttl: Duration,
    tokens: Mutex<Vec<Live>>,
}

impl std::fmt::Debug for LocalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalSession")
    }
}

impl Default for LocalSession {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalSession {
    pub fn new() -> Self {
        Self {
            ttl: SESSION_TTL,
            tokens: Mutex::new(Vec::new()),
        }
    }

    /// A session with no secret kept on disk. The store starts empty: a token
    /// only exists after the opening link is redeemed.
    pub fn random() -> Result<Self, SessionError> {
        Ok(Self::new())
    }

    /// Seeds the store with one known token, live at the current time.
    #[doc(hidden)]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let session = Self::new();
        if let Ok(mut tokens) = session.tokens.lock() {
            tokens.push(Live {
                value: secret,
                issued: Instant::now(),
            });
        }
        session
    }

    /// Mints a fresh single session token, drops expired ones, and returns it
    /// as hex. Called only when a live opening code is redeemed.
    pub fn issue(&self) -> Option<String> {
        let value = random_bytes()?;
        let mut tokens = self.tokens.lock().ok()?;
        let now = Instant::now();
        tokens.retain(|token| now.duration_since(token.issued) < self.ttl);
        if tokens.len() >= MAX_LIVE_TOKENS {
            tokens.remove(0);
        }
        tokens.push(Live { value, issued: now });
        Some(hex::encode(value))
    }

    /// True when the `Authorization` header carries a live, non-expired token
    /// minted by this process. No cookie is read.
    pub fn accepts(&self, authorization: Option<&str>) -> bool {
        let Some(offered) = authorization.and_then(parse_bearer) else {
            return false;
        };
        let Ok(mut tokens) = self.tokens.lock() else {
            return false;
        };
        let now = Instant::now();
        tokens.retain(|token| now.duration_since(token.issued) < self.ttl);
        let mut matched = false;
        for token in tokens.iter() {
            matched |= bool::from(token.value.as_slice().ct_eq(offered.as_slice()));
        }
        matched
    }
}

/// Parses `Authorization: Bearer <64 hex>` into 32 bytes. Rejects anything
/// else, including an over-long header.
fn parse_bearer(header: &str) -> Option<[u8; 32]> {
    if header.len() > 4096 {
        return None;
    }
    let (scheme, value) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
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

pub(crate) fn random_bytes() -> Option<[u8; 32]> {
    let mut secret = [0u8; 32];
    let mut source = fs::File::open("/dev/urandom").ok()?;
    source.read_exact(&mut secret).ok()?;
    Some(secret)
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
    fn a_minted_token_is_accepted_and_a_foreign_one_is_not() {
        let session = LocalSession::new();
        assert!(!session.accepts(None));
        let token = session.issue().unwrap();
        let header = format!("Bearer {token}");
        assert!(session.accepts(Some(&header)));
        // A token minted by another process (another store) does not match.
        let other = LocalSession::new();
        let other_token = other.issue().unwrap();
        assert!(!session.accepts(Some(&format!("Bearer {other_token}"))));
        // No token at all, or a cookie, is refused.
        assert!(!session.accepts(Some("Bearer")));
        assert!(!session.accepts(Some(&format!("praetore_consola={token}"))));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let session = LocalSession {
            ttl: Duration::ZERO,
            tokens: Mutex::new(Vec::new()),
        };
        let token = session.issue().unwrap();
        assert!(!session.accepts(Some(&format!("Bearer {token}"))));
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
