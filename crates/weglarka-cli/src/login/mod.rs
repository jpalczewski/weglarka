//! `weglarka login | logout | whoami`: sign in to a remote host with the OAuth 2.0 device
//! authorization grant (RFC 8628), keep the tokens, refresh them on use (docs/decisions/0060).
//!
//! The CLI is a *public* client of the identity provider (no secret, nothing to leak from a
//! workstation); it treats the access token as opaque — the daemon verifies it. Tokens live in
//! `credentials.toml` and never reach stdout, stderr, logs or errors.

mod credentials;
mod discovery;
pub(crate) mod remote;
mod transport;

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use serde::Serialize;
use weglarka_oidc::{
    ClientAuth, DeviceAuthorization, DevicePoll, DiscoveryPolicy, Endpoints, Secret, TokenSet,
    Transport,
};

use self::credentials::{HostEntry, Store, normalize_host};
use self::transport::HyperTransport;
use crate::error::{CliError, Kind};
use crate::output::emit;

/// The scopes the CLI asks for: `groups` maps the person to the daemon's scopes,
/// `offline_access` gives the refresh token that keeps the session alive.
const SCOPE: &str = "openid profile groups offline_access";
/// The one hint for every "sign in (again)" error; the issuer and audience come from the host.
const LOGIN_HINT: &str = "run `weglarka --host <url> login`";
/// A token with less than this left is refreshed before use.
const REFRESH_SKEW_SECS: u64 = 60;

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// The identity provider's issuer URL, e.g. `https://auth.example.com`. Default: the one the
    /// host publishes; given, it must equal that.
    #[arg(long, value_name = "URL")]
    pub issuer: Option<String>,
    /// The `[admin.http] audience` of the host (a token must carry it). Default: the one the host
    /// publishes; given, it must equal that. With both flags nothing is fetched from the host.
    #[arg(long, value_name = "URL")]
    pub audience: Option<String>,
    /// The provider's client id of the CLI (a public client with `device_flow = true`).
    #[arg(long, default_value = "weglarka-cli", value_name = "ID")]
    pub client_id: String,
}

#[derive(Debug, Serialize)]
struct Session {
    host: String,
    /// Seconds until the access token needs refreshing.
    expires_in_secs: u64,
    /// Whether a refresh token is kept, i.e. the session outlives the access token.
    refreshable: bool,
}

#[derive(Debug, Serialize)]
struct LoggedOut {
    host: String,
    /// The provider was told to revoke the refresh token (best effort; the local copy is gone either way).
    revoked: bool,
}

/// What a sign-in is about; every login method (device grant now, `--browser` later) starts from one.
#[derive(Debug)]
struct LoginTarget {
    host: String,
    issuer: String,
    audience: String,
    client_id: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn http() -> Result<HyperTransport, CliError> {
    HyperTransport::new().map_err(|e| CliError::internal(format!("cannot set up TLS: {e}")))
}

fn provider_error(e: weglarka_oidc::Error) -> CliError {
    use weglarka_oidc::Error as E;
    match e {
        E::Network(m) => CliError::new(
            Kind::Unreachable,
            format!("cannot reach the identity provider: {m}"),
        ),
        E::Discovery(m) => CliError::new(Kind::Config, format!("provider discovery failed: {m}"))
            .with_hint(format!(
                "the issuer comes from the host (or --issuer); {LOGIN_HINT}"
            )),
        // A rate limit or a short outage: nothing stored is dropped, the next command tries again.
        E::Throttled {
            status,
            retry_after,
        } => CliError::new(
            Kind::Unreachable,
            format!("the identity provider asked to retry later (HTTP {status})"),
        )
        .with_hint(match retry_after {
            Some(wait) => format!("try again in {} s", wait.as_secs().max(1)),
            None => "try again in a minute".to_owned(),
        }),
        other => CliError::internal(other.to_string()),
    }
}

/// `host` is the global `--host` (or `cli.toml`): where to sign in.
pub async fn login(json: bool, host: Option<&str>, args: LoginArgs) -> Result<i32, CliError> {
    let host = host.ok_or_else(|| CliError::usage("which host?").with_hint(LOGIN_HINT))?;
    let host = normalize_host(host)?;
    let transport = http()?;
    let store = Store::default_location()?;
    let target = discovery::resolve_target(&transport, &store, &host, &args).await?;
    // Always shown: the first login is the one the host controls (see `discovery`).
    eprintln!("Signing in to {} with {}", target.host, target.issuer);
    let session = device_login(
        &transport,
        &store,
        &target,
        now_secs(),
        tokio::time::sleep,
        show_instructions,
        |line| eprintln!("{line}"),
    )
    .await?;
    emit(json, &session, || {
        format!("Signed in to {}.\n", session.host)
    });
    Ok(0)
}

fn show_instructions(auth: &DeviceAuthorization) {
    eprintln!("To sign in, open  {}", auth.verification_uri);
    eprintln!("and enter the code  {}", auth.user_code);
    if let Some(complete) = &auth.verification_uri_complete {
        eprintln!("(or open {complete} directly)");
    }
    eprintln!(
        "Waiting for approval (the code is valid for {} minutes)…",
        auth.expires_in.as_secs().div_ceil(60)
    );
}

/// Discovery, the device grant and saving the session, in that order.
async fn device_login<T, F>(
    transport: &T,
    store: &Store,
    target: &LoginTarget,
    now: u64,
    sleep: impl Fn(Duration) -> F,
    show: impl FnOnce(&DeviceAuthorization),
    note: impl Fn(&str),
) -> Result<Session, CliError>
where
    T: Transport,
    F: Future<Output = ()>,
{
    let endpoints = weglarka_oidc::discover(transport, &target.issuer, &DiscoveryPolicy::default())
        .await
        .map_err(provider_error)?;
    let (tokens, waited) = device_grant(transport, &endpoints, target, sleep, show, note).await?;
    // `now` was taken before the person approved; the token is as old as the time spent waiting.
    save_session(store, target, &tokens, now + waited.as_secs())
}

/// RFC 8628: asks for a code, shows it and polls until the person approves. Returns the tokens and
/// how long the person took.
async fn device_grant<T, F>(
    transport: &T,
    endpoints: &Endpoints,
    target: &LoginTarget,
    sleep: impl Fn(Duration) -> F,
    show: impl FnOnce(&DeviceAuthorization),
    note: impl Fn(&str),
) -> Result<(TokenSet, Duration), CliError>
where
    T: Transport,
    F: Future<Output = ()>,
{
    let device_endpoint = endpoints.device_authorization.as_ref().ok_or_else(|| {
        CliError::new(
            Kind::Config,
            "the identity provider does not offer the device authorization grant",
        )
        .with_hint("it must list `device_authorization_endpoint` in its discovery document")
    })?;
    let auth = weglarka_oidc::device_authorization(
        transport,
        device_endpoint,
        &target.client_id,
        SCOPE,
        &target.audience,
    )
    .await
    .map_err(|e| match e {
        weglarka_oidc::Error::Refused(_) => CliError::new(
            Kind::Config,
            "the identity provider refused the sign-in request",
        )
        .with_hint(format!(
            "is `{}` a public client with `device_flow = true` and the scopes `{SCOPE}`?",
            target.client_id
        )),
        other => provider_error(other),
    })?;
    show(&auth);

    let mut interval = auth.interval;
    let mut waited = Duration::ZERO;
    let mut throttled = false;
    let tokens = loop {
        let slept = interval;
        sleep(slept).await;
        waited += slept;
        match weglarka_oidc::poll_device_token(
            transport,
            &endpoints.token,
            &target.client_id,
            &auth.device_code,
            interval,
        )
        .await
        .map_err(provider_error)?
        {
            DevicePoll::Approved(tokens) => break tokens,
            DevicePoll::Pending { interval: next } => {
                interval = next;
                throttled = false;
            }
            DevicePoll::Throttled { interval: next } => {
                interval = next;
                // One note per streak: the person is told once, the log is not flooded.
                if !std::mem::replace(&mut throttled, true) {
                    note(
                        "The identity provider is rate limiting the sign-in; still waiting, polling more slowly…",
                    );
                }
            }
            DevicePoll::Denied => {
                return Err(CliError::internal("the sign-in was denied"));
            }
            DevicePoll::Expired => return Err(expired()),
        }
        if waited >= auth.expires_in {
            return Err(expired());
        }
    };

    Ok((tokens, waited))
}

/// Stores the tokens of a finished sign-in under the host; `issued` is when they were handed out.
fn save_session(
    store: &Store,
    target: &LoginTarget,
    tokens: &TokenSet,
    issued: u64,
) -> Result<Session, CliError> {
    let session = Session {
        host: target.host.clone(),
        expires_in_secs: tokens.expires_in.as_secs(),
        refreshable: tokens.refresh.is_some(),
    };
    store.update(|c| {
        c.hosts.insert(
            target.host.clone(),
            HostEntry {
                issuer: target.issuer.clone(),
                client_id: target.client_id.clone(),
                audience: target.audience.clone(),
                access_token: tokens.access.expose().to_owned(),
                access_expires: issued + tokens.expires_in.as_secs(),
                refresh_token: tokens.refresh.as_ref().map(|t| t.expose().to_owned()),
            },
        );
    })?;
    Ok(session)
}

fn expired() -> CliError {
    CliError::internal("the sign-in code expired before it was approved")
        .with_hint("run `weglarka login` again")
}

fn not_signed_in(host: &str) -> CliError {
    CliError::new(Kind::NotFound, format!("not signed in to {host}")).with_hint(LOGIN_HINT)
}

/// `--host`, or the only host that has credentials.
fn resolve_host(given: Option<&str>, store: &Store) -> Result<String, CliError> {
    if let Some(host) = given {
        return normalize_host(host);
    }
    let stored = store.read()?;
    let mut hosts = stored.hosts.keys();
    match (hosts.next(), hosts.next()) {
        (Some(only), None) => Ok(only.clone()),
        (None, _) => Err(CliError::new(Kind::NotFound, "not signed in to any host")
            .with_hint("run `weglarka login --host <url> …`")),
        (Some(_), Some(_)) => Err(CliError::usage("signed in to several hosts").with_hint(
            format!(
                "choose one with --host: {}",
                stored.hosts.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        )),
    }
}

/// A usable access token for `host`, refreshed first when it is about to expire. Holds the
/// credentials lock for the whole exchange so a concurrent CLI cannot spend the same refresh token.
async fn access_token<T: Transport>(
    transport: &T,
    store: &Store,
    host: &str,
    now: u64,
) -> Result<(Secret, Session), CliError> {
    let lock = store.lock()?;
    let mut credentials = lock.read()?;
    let entry = credentials
        .hosts
        .get_mut(host)
        .ok_or_else(|| not_signed_in(host))?;
    if entry.access_expires > now + REFRESH_SKEW_SECS {
        let session = Session {
            host: host.to_owned(),
            expires_in_secs: entry.access_expires - now,
            refreshable: entry.refresh_token.is_some(),
        };
        return Ok((Secret::new(entry.access_token.clone()), session));
    }
    let ended = || {
        CliError::new(Kind::NotFound, format!("the session with {host} has ended"))
            .with_hint("run `weglarka login` again")
    };
    let Some(refresh_token) = entry.refresh_token.clone() else {
        credentials.hosts.remove(host);
        lock.write(&credentials)?;
        return Err(ended());
    };
    let (issuer, client_id) = (entry.issuer.clone(), entry.client_id.clone());
    let endpoints = weglarka_oidc::discover(transport, &issuer, &DiscoveryPolicy::default())
        .await
        .map_err(provider_error)?;
    let refreshed = weglarka_oidc::refresh(
        transport,
        &endpoints.token,
        ClientAuth::Public { id: &client_id },
        &Secret::new(refresh_token),
        SCOPE,
    )
    .await;
    match refreshed {
        Ok(tokens) => {
            let entry = credentials
                .hosts
                .get_mut(host)
                .ok_or_else(|| not_signed_in(host))?;
            entry.access_token = tokens.access.expose().to_owned();
            entry.access_expires = now + tokens.expires_in.as_secs();
            // The provider may rotate the refresh token; keep the old one only if it did not.
            if let Some(rotated) = &tokens.refresh {
                entry.refresh_token = Some(rotated.expose().to_owned());
            }
            let session = Session {
                host: host.to_owned(),
                expires_in_secs: tokens.expires_in.as_secs(),
                refreshable: entry.refresh_token.is_some(),
            };
            lock.write(&credentials)?;
            Ok((tokens.access, session))
        }
        // The grant is gone (revoked, expired, rotated elsewhere): the stored tokens are useless.
        // Anything else (a rate limit, an outage, a misrouted proxy) keeps them for the next try.
        Err(e) if e.is_definitive() => {
            credentials.hosts.remove(host);
            lock.write(&credentials)?;
            Err(ended())
        }
        Err(e) => Err(provider_error(e)),
    }
}

pub async fn whoami(json: bool, host: Option<&str>) -> Result<i32, CliError> {
    let store = Store::default_location()?;
    let host = resolve_host(host, &store)?;
    let (_token, session) = access_token(&http()?, &store, &host, now_secs()).await?;
    emit(json, &session, || {
        format!(
            "Signed in to {} (token valid for {} min{}).\n",
            session.host,
            session.expires_in_secs / 60,
            if session.refreshable {
                ", renewable"
            } else {
                ""
            }
        )
    });
    Ok(0)
}

pub async fn logout(json: bool, host: Option<&str>) -> Result<i32, CliError> {
    let store = Store::default_location()?;
    let host = resolve_host(host, &store)?;
    let result = sign_out(&http()?, &store, &host).await?;
    emit(json, &result, || {
        if result.revoked {
            format!(
                "Signed out of {}; the provider revoked the session.\n",
                result.host
            )
        } else {
            format!(
                "Signed out of {} (the provider was not told).\n",
                result.host
            )
        }
    });
    Ok(0)
}

async fn sign_out<T: Transport>(
    transport: &T,
    store: &Store,
    host: &str,
) -> Result<LoggedOut, CliError> {
    // The local copy goes first: whatever the provider does, nothing stays on disk.
    let entry = store
        .update(|c| c.hosts.remove(host))?
        .ok_or_else(|| not_signed_in(host))?;
    let mut revoked = false;
    if let Some(refresh_token) = entry.refresh_token
        && let Ok(endpoints) =
            weglarka_oidc::discover(transport, &entry.issuer, &DiscoveryPolicy::default()).await
        && let Some(endpoint) = &endpoints.revocation
    {
        revoked = weglarka_oidc::revoke(
            transport,
            endpoint,
            ClientAuth::Public {
                id: &entry.client_id,
            },
            &Secret::new(refresh_token),
        )
        .await
        .is_ok();
    }
    Ok(LoggedOut {
        host: host.to_owned(),
        revoked,
    })
}

#[cfg(test)]
mod tests;
