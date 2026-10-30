//! `weglarka login | logout | whoami`: sign in to a remote host with the OAuth 2.0 device
//! authorization grant (RFC 8628), keep the tokens, refresh them on use (docs/decisions/0060).
//!
//! The CLI is a *public* client of the identity provider (no secret, nothing to leak from a
//! workstation); it treats the access token as opaque — the daemon verifies it. Tokens live in
//! `credentials.toml` and never reach stdout, stderr, logs or errors.

mod credentials;
pub(crate) mod remote;
mod transport;

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use serde::Serialize;
use weglarka_oidc::{
    ClientAuth, DeviceAuthorization, DevicePoll, DiscoveryPolicy, Secret, Transport,
};

use self::credentials::{HostEntry, Store, normalize_host};
use self::transport::HyperTransport;
use crate::error::{CliError, Kind};
use crate::output::emit;

/// The scopes the CLI asks for: `groups` maps the person to the daemon's scopes,
/// `offline_access` gives the refresh token that keeps the session alive.
const SCOPE: &str = "openid profile groups offline_access";
/// A token with less than this left is refreshed before use.
const REFRESH_SKEW_SECS: u64 = 60;

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// The identity provider's issuer URL, e.g. `https://auth.example.com`.
    #[arg(long, value_name = "URL")]
    pub issuer: String,
    /// The `[admin.http] audience` of the host (a token must carry it).
    #[arg(long, value_name = "URL")]
    pub audience: String,
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

struct LoginRequest {
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
            .with_hint("check --issuer: it must be the provider's exact issuer URL"),
        other => CliError::internal(other.to_string()),
    }
}

/// `host` is the global `--host` (or `cli.toml`): where to sign in.
pub async fn login(json: bool, host: Option<&str>, args: LoginArgs) -> Result<i32, CliError> {
    let host = host.ok_or_else(|| {
        CliError::usage("which host?").with_hint(
            "pass the panel's address: `weglarka --host https://panel.example.com login --issuer … --audience …`",
        )
    })?;
    let request = LoginRequest {
        host: normalize_host(host)?,
        issuer: args.issuer.trim().to_owned(),
        audience: args.audience.trim().to_owned(),
        client_id: args.client_id,
    };
    let session = device_login(
        &http()?,
        &Store::default_location()?,
        &request,
        now_secs(),
        tokio::time::sleep,
        show_instructions,
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

async fn device_login<T, F>(
    transport: &T,
    store: &Store,
    request: &LoginRequest,
    now: u64,
    sleep: impl Fn(Duration) -> F,
    show: impl FnOnce(&DeviceAuthorization),
) -> Result<Session, CliError>
where
    T: Transport,
    F: Future<Output = ()>,
{
    let endpoints =
        weglarka_oidc::discover(transport, &request.issuer, &DiscoveryPolicy::default())
            .await
            .map_err(provider_error)?;
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
        &request.client_id,
        SCOPE,
        &request.audience,
    )
    .await
    .map_err(|e| match e {
        weglarka_oidc::Error::Refused(_) => CliError::new(
            Kind::Config,
            "the identity provider refused the sign-in request",
        )
        .with_hint(format!(
            "is `{}` a public client with `device_flow = true` and the scopes `{SCOPE}`?",
            request.client_id
        )),
        other => provider_error(other),
    })?;
    show(&auth);

    let mut interval = auth.interval;
    let mut waited = Duration::ZERO;
    let tokens = loop {
        sleep(interval).await;
        waited += interval;
        match weglarka_oidc::poll_device_token(
            transport,
            &endpoints.token,
            &request.client_id,
            &auth.device_code,
            interval,
        )
        .await
        .map_err(provider_error)?
        {
            DevicePoll::Approved(tokens) => break tokens,
            DevicePoll::Pending { interval: next } => interval = next,
            DevicePoll::Denied => {
                return Err(CliError::internal("the sign-in was denied"));
            }
            DevicePoll::Expired => return Err(expired()),
        }
        if waited >= auth.expires_in {
            return Err(expired());
        }
    };

    let session = Session {
        host: request.host.clone(),
        expires_in_secs: tokens.expires_in.as_secs(),
        refreshable: tokens.refresh.is_some(),
    };
    // `now` was taken before the person approved; the token is as old as the time spent waiting.
    let issued = now + waited.as_secs();
    store.update(|c| {
        c.hosts.insert(
            request.host.clone(),
            HostEntry {
                issuer: request.issuer.clone(),
                client_id: request.client_id.clone(),
                audience: request.audience.clone(),
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
    CliError::new(Kind::NotFound, format!("not signed in to {host}"))
        .with_hint("run `weglarka login --host <url> --issuer <url> --audience <url>`")
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
