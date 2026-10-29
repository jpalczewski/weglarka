//! Server-side sessions and pending logins (docs/decisions/0057).
//!
//! The browser holds one opaque cookie; the user's tokens never leave this process. A [`Session`]
//! keeps them in memory behind [`Secret`] (redacting `Debug`, no `Serialize`), so a restart signs
//! everybody out, which is the intended failure mode.
//!
//! - [`SessionStore`]: id → session, bounded, with an absolute and an idle lifetime;
//! - [`PendingLogins`]: the `state`/`nonce`/PKCE verifier of logins that were started and not yet
//!   completed, keyed by a short-lived cookie and deleted at the callback;
//! - [`Clock`]: `Instant::now()` plus an adjustable skew, so tests can age sessions without sleeping.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::config::Secret;
use crate::secure::random_token;

/// Sessions held at once; a login beyond it is refused rather than evicting somebody.
pub const MAX_SESSIONS: usize = 1024;
/// Logins started and not completed.
pub const MAX_PENDING_LOGINS: usize = 1024;
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
        Instant::now() + Duration::from_millis(self.skew_millis.load(Ordering::Relaxed))
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
        if map.len() >= self.capacity {
            return Err(Full);
        }
        let id = random_token();
        map.insert(id.clone(), Arc::new(session));
        Ok(id)
    }

    /// The live session for `id`, with its idle timer reset. An expired one is ended and removed.
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        let now = self.clock.now();
        let mut map = self.lock();
        let session = map.get(id)?.clone();
        if session.is_ended() || session.expired(now, self.idle, self.max) {
            map.remove(id);
            session.end();
            return None;
        }
        session.touch(now);
        Some(session)
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
    created: Instant,
}

impl PendingLogin {
    pub fn new(
        state: String,
        nonce: String,
        verifier: Secret,
        return_to: String,
        now: Instant,
    ) -> Self {
        Self {
            state,
            nonce,
            verifier,
            return_to,
            created: now,
        }
    }
}

pub struct PendingLogins {
    map: Mutex<HashMap<String, PendingLogin>>,
    capacity: usize,
    clock: Clock,
}

impl PendingLogins {
    pub fn new(clock: Clock) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            capacity: MAX_PENDING_LOGINS,
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingLogin>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stores a started login and returns the id for its cookie.
    pub fn insert(&self, login: PendingLogin) -> Result<String, Full> {
        let now = self.clock.now();
        let mut map = self.lock();
        map.retain(|_, l| now.saturating_duration_since(l.created) < PENDING_LOGIN_TTL);
        if map.len() >= self.capacity {
            return Err(Full);
        }
        let id = random_token();
        map.insert(id.clone(), login);
        Ok(id)
    }

    /// Removes and returns the login: one answer per started login, whatever its outcome.
    pub fn take(&self, id: &str) -> Option<PendingLogin> {
        let login = self.lock().remove(id)?;
        let age = self.clock.now().saturating_duration_since(login.created);
        (age < PENDING_LOGIN_TTL).then_some(login)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    #[test]
    fn pending_logins_are_single_use_and_expire() {
        let clock = Clock::default();
        let logins = PendingLogins::new(clock.clone());
        let new = |clock: &Clock| {
            PendingLogin::new(
                "s".into(),
                "n".into(),
                Secret::new("v"),
                "/".into(),
                clock.now(),
            )
        };
        let id = logins.insert(new(&clock)).unwrap();
        assert!(logins.take(&id).is_some());
        assert!(logins.take(&id).is_none());

        let id = logins.insert(new(&clock)).unwrap();
        clock.advance(PENDING_LOGIN_TTL);
        assert!(logins.take(&id).is_none());
        assert!(logins.is_empty());
    }

    #[test]
    fn debug_shows_no_token() {
        let clock = Clock::default();
        let s = session(&clock);
        let shown = format!("{s:?}");
        assert!(!shown.contains("access-token-value"), "{shown}");
    }
}
