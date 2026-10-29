//! Server-side sessions and pending logins (docs/decisions/0057).
//!
//! The browser holds one opaque cookie; the user's tokens never leave this process. A [`Session`]
//! keeps them in memory behind [`Secret`] (redacting `Debug`, no `Serialize`), so a restart signs
//! everybody out, which is the intended failure mode.
//!
//! - [`SessionStore`]: id → session, bounded, with an absolute and an idle lifetime;
//! - [`PendingLogins`]: the `state`/`nonce`/PKCE verifier of logins that were started and not yet
//!   completed. They live in the browser, in a short-lived cookie sealed with an AEAD key that exists
//!   only in this process, so an anonymous `GET /auth/login` costs the server no memory;
//! - [`Clock`]: `Instant::now()` plus an adjustable skew, so tests can age sessions without sleeping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::config::Secret;
use crate::secure::random_token;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Sessions held at once; a login beyond it is refused rather than evicting somebody.
pub const MAX_SESSIONS: usize = 1024;
/// Sessions one identity may hold; a further login evicts that identity's oldest, so one account
/// looping through the login flow without a cookie cannot fill the table for everybody else.
pub const MAX_SESSIONS_PER_SUB: usize = 5;
/// Login states remembered as used (see [`PendingLogins`]).
pub const MAX_USED_STATES: usize = 4096;
/// How long a started login may take (the user types a password and maybe a second factor).
pub const PENDING_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);
/// How often dead sessions are swept even when nobody logs in.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// The time source of the stores. Production never moves it; a test calls [`Clock::advance`].
#[derive(Debug, Clone, Default)]
pub struct Clock {
    skew_millis: Arc<AtomicU64>,
}

impl Clock {
    pub fn now(&self) -> Instant {
        Instant::now() + self.skew()
    }

    /// Wall-clock seconds since the Unix epoch, moved by the same skew; for values that leave the
    /// process (the login cookie's expiry).
    pub fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.skew().as_secs()
    }

    fn skew(&self) -> Duration {
        Duration::from_millis(self.skew_millis.load(Ordering::Relaxed))
    }

    /// Moves every reader of this clock forward. For tests.
    #[doc(hidden)]
    pub fn advance(&self, by: Duration) {
        self.skew_millis
            .fetch_add(by.as_millis() as u64, Ordering::Relaxed);
    }
}

/// Who is signed in, for display. Never used for authorization: the daemon decides from the token.
#[derive(Debug, Clone)]
pub struct User {
    pub sub: String,
    pub name: String,
}

/// What `require_session` puts in the request extensions for handlers: the caller's own access
/// token (to hand to the daemon client), the CSRF token for forms, and the user.
#[derive(Clone)]
pub struct SessionView {
    pub token: Arc<Secret>,
    pub csrf: String,
    pub user: User,
}

impl std::fmt::Debug for SessionView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionView")
            .field("user", &self.user)
            .field("token", &"<redacted>")
            .field("csrf", &"<redacted>")
            .finish()
    }
}

/// The tokens of one session; locked while a refresh runs, so only one refresh is in flight.
pub struct Tokens {
    pub access: Arc<Secret>,
    pub refresh: Option<Secret>,
    pub access_expires: Instant,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tokens(<redacted>)")
    }
}

pub struct Session {
    pub user: User,
    /// Checked on every state-changing request; separate from the session id so a page can carry it.
    pub csrf: String,
    created: Instant,
    last_seen: Mutex<Instant>,
    /// Also the refresh lock: whoever holds it may refresh, the others then see the new token.
    pub tokens: tokio::sync::Mutex<Tokens>,
    ended: watch::Sender<bool>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("user", &self.user)
            .field("ended", &self.is_ended())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(user: User, tokens: Tokens, now: Instant) -> Self {
        Self {
            user,
            csrf: random_token(),
            created: now,
            last_seen: Mutex::new(now),
            tokens: tokio::sync::Mutex::new(tokens),
            ended: watch::channel(false).0,
        }
    }

    /// Flips to `true` when the session ends (logout, expiry, failed refresh). Long-lived streams
    /// tied to the session wait on it and close.
    pub fn ended(&self) -> watch::Receiver<bool> {
        self.ended.subscribe()
    }

    pub fn is_ended(&self) -> bool {
        *self.ended.borrow()
    }

    pub fn end(&self) {
        self.ended.send_replace(true);
    }

    fn expired(&self, now: Instant, idle: Duration, max: Duration) -> bool {
        let last = *self.last_seen.lock().unwrap_or_else(|e| e.into_inner());
        now.saturating_duration_since(self.created) >= max
            || now.saturating_duration_since(last) >= idle
    }

    fn touch(&self, now: Instant) {
        *self.last_seen.lock().unwrap_or_else(|e| e.into_inner()) = now;
    }
}

#[derive(Debug, thiserror::Error)]
#[error("too many sessions or pending logins")]
pub struct Full;

pub struct SessionStore {
    map: Mutex<HashMap<String, Arc<Session>>>,
    idle: Duration,
    max: Duration,
    capacity: usize,
    clock: Clock,
}

impl SessionStore {
    pub fn new(idle: Duration, max: Duration, clock: Clock) -> Self {
        Self::with_capacity(idle, max, clock, MAX_SESSIONS)
    }

    pub fn with_capacity(idle: Duration, max: Duration, clock: Clock, capacity: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            idle,
            max,
            capacity,
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Session>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stores `session` under a fresh random id (never one the browser sent) and returns the id.
    pub fn insert(&self, session: Session) -> Result<String, Full> {
        let now = self.clock.now();
        let mut map = self.lock();
        if map.len() >= self.capacity {
            Self::drop_dead(&mut map, now, self.idle, self.max);
        }
        // The identity's own oldest sessions make room for the new one.
        let sub = session.user.sub.clone();
        let mut mine: Vec<(Instant, String)> = map
            .iter()
            .filter(|(_, s)| s.user.sub == sub)
            .map(|(id, s)| (s.created, id.clone()))
            .collect();
        if mine.len() >= MAX_SESSIONS_PER_SUB {
            mine.sort();
            for (_, id) in mine.drain(..mine.len() + 1 - MAX_SESSIONS_PER_SUB) {
                if let Some(old) = map.remove(&id) {
                    old.end();
                }
            }
        }
        if map.len() >= self.capacity {
            return Err(Full);
        }
        let id = random_token();
        map.insert(id.clone(), Arc::new(session));
        Ok(id)
    }

    /// The live session for `id`, with its idle timer reset. An expired one is ended and removed.
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        let session = self.peek(id)?;
        self.touch(&session);
        Some(session)
    }

    /// Like [`SessionStore::get`] but leaves the idle timer alone: a request that has not proved
    /// itself (CSRF) must not keep a session alive. Call [`SessionStore::touch`] once it has.
    pub fn peek(&self, id: &str) -> Option<Arc<Session>> {
        let now = self.clock.now();
        let mut map = self.lock();
        let session = map.get(id)?.clone();
        if session.is_ended() || session.expired(now, self.idle, self.max) {
            map.remove(id);
            session.end();
            return None;
        }
        Some(session)
    }

    pub fn touch(&self, session: &Session) {
        session.touch(self.clock.now());
    }

    /// Ends and forgets the session.
    pub fn remove(&self, id: &str) {
        if let Some(session) = self.lock().remove(id) {
            session.end();
        }
    }

    /// Ends and drops every dead session; returns how many.
    pub fn sweep(&self) -> usize {
        Self::drop_dead(&mut self.lock(), self.clock.now(), self.idle, self.max)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn drop_dead(
        map: &mut HashMap<String, Arc<Session>>,
        now: Instant,
        idle: Duration,
        max: Duration,
    ) -> usize {
        let before = map.len();
        map.retain(|_, s| {
            let dead = s.is_ended() || s.expired(now, idle, max);
            if dead {
                s.end();
            }
            !dead
        });
        before - map.len()
    }

    /// Sweeps in the background until the store is dropped. Needs a running tokio runtime.
    pub fn spawn_sweeper(self: &Arc<Self>) {
        let store: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            loop {
                tick.tick().await;
                match store.upgrade() {
                    Some(store) => {
                        store.sweep();
                    }
                    None => return,
                }
            }
        });
    }
}

/// What the callback needs to finish a login that was started in this browser.
pub struct PendingLogin {
    pub state: String,
    pub nonce: String,
    pub verifier: Secret,
    /// A local absolute path, already validated.
    pub return_to: String,
}

/// Wire form of [`PendingLogin`] inside the sealed cookie. `Secret` has no `Serialize` (by design),
/// so the verifier crosses as a plain string here and never leaves this module in that form.
#[derive(Serialize, Deserialize)]
struct Sealed {
    state: String,
    nonce: String,
    verifier: String,
    return_to: String,
    /// Unix seconds.
    exp: u64,
}

const LOGIN_AAD: &[u8] = b"weglarka-panel login cookie v1";

/// Pending logins without server-side storage (#292). `/auth/login` seals the login into the cookie
/// value with ChaCha20-Poly1305 under a key drawn at start-up and never written anywhere: the
/// browser can neither read nor change it, and a restart invalidates logins in flight, exactly as
/// it ends every session (those are in memory too). A random per-process key was chosen over one
/// derived from the client secret (HKDF) because it couples nothing to the secret's rotation and
/// there is no second process that would need to open the same cookie.
///
/// Single use is kept by remembering the `state` of every cookie that reached the callback until
/// it would have expired anyway. That set only grows from cookies this process sealed (a forged
/// cookie does not open), and when a flood of genuine ones fills it the entry closest to expiry is
/// dropped instead of refusing logins: replay protection degrades first, availability does not. The
/// authorization code is single use at the provider, so a replay needs more than the cookie.
pub struct PendingLogins {
    key: LessSafeKey,
    used: Mutex<HashMap<String, u64>>,
    clock: Clock,
}

impl PendingLogins {
    pub fn new(clock: Clock) -> Self {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .expect("the operating system cannot provide random bytes");
        let key = UnboundKey::new(&CHACHA20_POLY1305, &key).expect("a 32-byte ChaCha20 key");
        Self {
            key: LessSafeKey::new(key),
            used: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// The cookie value for a started login (base64url: nonce, ciphertext and tag).
    pub fn seal(&self, login: &PendingLogin) -> String {
        let plain = serde_json::to_vec(&Sealed {
            state: login.state.clone(),
            nonce: login.nonce.clone(),
            verifier: login.verifier.expose().to_owned(),
            return_to: login.return_to.clone(),
            exp: self.clock.unix_secs() + PENDING_LOGIN_TTL.as_secs(),
        })
        .expect("a login serializes");
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("the operating system cannot provide random bytes");
        let mut buf = plain;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(LOGIN_AAD),
                &mut buf,
            )
            .expect("sealing cannot fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        URL_SAFE_NO_PAD.encode(out)
    }

    /// Opens a cookie and consumes it: `None` if it is forged, expired or already used. A login
    /// answers once, whatever its outcome.
    pub fn open(&self, cookie: &str) -> Option<PendingLogin> {
        let raw = URL_SAFE_NO_PAD.decode(cookie).ok()?;
        if raw.len() <= NONCE_LEN {
            return None;
        }
        let (nonce, sealed) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = sealed.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(LOGIN_AAD), &mut buf)
            .ok()?;
        let sealed: Sealed = serde_json::from_slice(plain).ok()?;
        let now = self.clock.unix_secs();
        if sealed.exp <= now {
            return None;
        }
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        if used.len() >= MAX_USED_STATES {
            used.retain(|_, exp| *exp > now);
        }
        if used.len() >= MAX_USED_STATES
            && let Some(oldest) = used
                .iter()
                .min_by_key(|(_, exp)| **exp)
                .map(|(k, _)| k.clone())
        {
            used.remove(&oldest);
        }
        if used.insert(sealed.state.clone(), sealed.exp).is_some() {
            return None;
        }
        Some(PendingLogin {
            state: sealed.state,
            nonce: sealed.nonce,
            verifier: Secret::new(sealed.verifier),
            return_to: sealed.return_to,
        })
    }

    /// States remembered as used.
    pub fn used_len(&self) -> usize {
        self.used.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(clock: &Clock) -> Session {
        Session::new(
            User {
                sub: "alice".into(),
                name: "Alice".into(),
            },
            Tokens {
                access: Arc::new(Secret::new("access-token-value")),
                refresh: None,
                access_expires: clock.now() + Duration::from_secs(300),
            },
            clock.now(),
        )
    }

    fn store(clock: &Clock) -> SessionStore {
        SessionStore::with_capacity(
            Duration::from_secs(60),
            Duration::from_secs(600),
            clock.clone(),
            2,
        )
    }

    #[test]
    fn idle_and_absolute_limits() {
        let clock = Clock::default();
        let store = store(&clock);
        let id = store.insert(session(&clock)).unwrap();
        let s = store.get(&id).unwrap();
        // Activity resets the idle timer, but never the absolute one.
        for _ in 0..10 {
            clock.advance(Duration::from_secs(59));
            assert!(store.get(&id).is_some());
        }
        clock.advance(Duration::from_secs(59));
        assert!(store.get(&id).is_none(), "past the absolute lifetime");
        assert!(s.is_ended());

        let id = store.insert(session(&clock)).unwrap();
        clock.advance(Duration::from_secs(61));
        assert!(store.get(&id).is_none(), "idle");
    }

    #[test]
    fn capacity_is_enforced_after_sweeping() {
        let clock = Clock::default();
        let store = store(&clock);
        store.insert(session(&clock)).unwrap();
        store.insert(session(&clock)).unwrap();
        assert!(store.insert(session(&clock)).is_err());
        clock.advance(Duration::from_secs(61));
        store.insert(session(&clock)).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn ended_flips_on_remove_and_sweep() {
        let clock = Clock::default();
        let store = store(&clock);
        let id = store.insert(session(&clock)).unwrap();
        let s = store.get(&id).unwrap();
        let rx = s.ended();
        assert!(!*rx.borrow());
        store.remove(&id);
        assert!(*rx.borrow());

        let id2 = store.insert(session(&clock)).unwrap();
        let rx2 = store.get(&id2).unwrap().ended();
        clock.advance(Duration::from_secs(120));
        assert_eq!(store.sweep(), 1);
        assert!(*rx2.borrow());
    }

    fn login(n: &str) -> PendingLogin {
        PendingLogin {
            state: format!("state-{n}"),
            nonce: format!("nonce-{n}"),
            verifier: Secret::new(format!("verifier-{n}")),
            return_to: "/apps".into(),
        }
    }

    #[test]
    fn pending_logins_are_single_use_and_expire() {
        let clock = Clock::default();
        let logins = PendingLogins::new(clock.clone());
        let cookie = logins.seal(&login("a"));
        let opened = logins.open(&cookie).unwrap();
        assert_eq!(opened.state, "state-a");
        assert_eq!(opened.nonce, "nonce-a");
        assert_eq!(opened.verifier.expose(), "verifier-a");
        assert_eq!(opened.return_to, "/apps");
        assert!(logins.open(&cookie).is_none(), "a replay");

        let cookie = logins.seal(&login("b"));
        clock.advance(PENDING_LOGIN_TTL);
        assert!(logins.open(&cookie).is_none(), "expired");
    }

    #[test]
    fn pending_login_cookies_cannot_be_forged_or_moved() {
        let clock = Clock::default();
        let logins = PendingLogins::new(clock.clone());
        let cookie = logins.seal(&login("a"));
        // Any flipped byte fails authentication.
        let mut raw = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(logins.open(&URL_SAFE_NO_PAD.encode(raw)).is_none());
        for junk in ["", "x", "not base64!", &random_token()] {
            assert!(logins.open(junk).is_none(), "{junk:?}");
        }
        // Another process (another key) cannot open it, and neither contains the verifier in clear.
        assert!(PendingLogins::new(clock).open(&cookie).is_none());
        assert!(!cookie.contains("verifier-a"));
        // The failed attempts did not consume it.
        assert!(logins.open(&cookie).is_some());
    }

    #[test]
    fn a_flood_of_logins_costs_no_memory_and_blocks_nobody() {
        let clock = Clock::default();
        let logins = PendingLogins::new(clock.clone());
        // Starting logins stores nothing, however many.
        let cookies: Vec<String> = (0..MAX_USED_STATES + 10)
            .map(|n| logins.seal(&login(&n.to_string())))
            .collect();
        assert_eq!(logins.used_len(), 0);
        // Completing them past the bound evicts the used-set, never refuses.
        for cookie in &cookies {
            assert!(logins.open(cookie).is_some());
        }
        assert_eq!(logins.used_len(), MAX_USED_STATES);
        let fresh = logins.seal(&login("legit"));
        assert!(logins.open(&fresh).is_some());
        assert!(logins.open(&fresh).is_none());
    }

    #[test]
    fn one_identity_holds_a_bounded_number_of_sessions() {
        let clock = Clock::default();
        let store = SessionStore::with_capacity(
            Duration::from_secs(60),
            Duration::from_secs(600),
            clock.clone(),
            100,
        );
        let ids: Vec<String> = (0..MAX_SESSIONS_PER_SUB + 3)
            .map(|_| {
                clock.advance(Duration::from_millis(5));
                store.insert(session(&clock)).unwrap()
            })
            .collect();
        assert_eq!(store.len(), MAX_SESSIONS_PER_SUB);
        // The oldest were evicted (and ended), the newest remain.
        for id in &ids[..3] {
            assert!(store.get(id).is_none());
        }
        for id in &ids[3..] {
            assert!(store.get(id).is_some());
        }
        // Somebody else is unaffected.
        let mut other = session(&clock);
        other.user.sub = "bob".into();
        store.insert(other).unwrap();
        assert_eq!(store.len(), MAX_SESSIONS_PER_SUB + 1);
    }

    #[test]
    fn debug_shows_no_token() {
        let clock = Clock::default();
        let s = session(&clock);
        let shown = format!("{s:?}");
        assert!(!shown.contains("access-token-value"), "{shown}");
    }
}
