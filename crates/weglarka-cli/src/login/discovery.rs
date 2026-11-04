//! Where `weglarka login` learns the issuer and audience: the host's own public document at
//! [`LOGIN_DISCOVERY_PATH`] (docs/decisions/0060, addendum), unless both are given as flags.
//!
//! Trust model: the host already receives the bearer token, so its audience changes nothing; the
//! issuer is what the host can abuse (a malicious host could name its own provider to phish
//! credentials). The CLI therefore always prints the issuer it is about to use, validates the
//! document, and refuses to replace the issuer or audience of a host it is already signed in to
//! (trust on first use, undone only by an explicit `logout`).

use weglarka_model::admin_auth::{LOGIN_DISCOVERY_PATH, LoginDiscovery, MAX_AUDIENCE_BYTES};
use weglarka_oidc::{Transport, Url};

use super::credentials::Store;
use super::{LoginArgs, LoginTarget};
use crate::error::{CliError, Kind};

/// The document is two short strings; anything bigger is the wrong thing.
const MAX_DOCUMENT_BYTES: usize = 4096;

fn config(message: impl Into<String>) -> CliError {
    CliError::new(Kind::Config, message)
}

fn pass_flags() -> &'static str {
    "pass --issuer and --audience yourself"
}

/// Fetches and validates the host's sign-in settings.
pub(super) async fn fetch<T: Transport>(
    transport: &T,
    host: &str,
) -> Result<LoginDiscovery, CliError> {
    let url = Url::parse(&format!("{host}{LOGIN_DISCOVERY_PATH}"))
        .map_err(|_| CliError::usage(format!("invalid --host {host:?}")))?;
    let response = transport
        .get(&url, MAX_DOCUMENT_BYTES)
        .await
        .map_err(|e| CliError::new(Kind::Unreachable, format!("cannot reach {host}: {e}")))?;
    match response.status {
        200..=299 => {}
        404 => {
            return Err(config("the host does not publish its sign-in settings")
                .with_hint(format!("it may run an older panel: {}", pass_flags())));
        }
        status => {
            return Err(CliError::new(
                Kind::Unreachable,
                format!("{host} answered HTTP {status} for its sign-in settings"),
            ));
        }
    }
    if response.body.len() > MAX_DOCUMENT_BYTES {
        return Err(config("the host's sign-in settings are too large"));
    }
    let document: LoginDiscovery = serde_json::from_slice(&response.body)
        .map_err(|_| config("the host's sign-in settings are not the expected JSON"))?;
    validate(&document)?;
    Ok(document)
}

fn loopback(url: &Url) -> bool {
    url.host_str()
        .map(|h| h.trim_matches(['[', ']']))
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback())
}

fn validate(document: &LoginDiscovery) -> Result<(), CliError> {
    let bad = |what: &str| config(format!("the host's sign-in settings are unusable: {what}"));
    // The raw string is kept, compared and printed, not the parsed form: a control character (a
    // terminal escape, a newline) must never reach the "Signing in with …" line.
    if document
        .issuer
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(bad("the issuer contains control or whitespace characters"));
    }
    let issuer = Url::parse(&document.issuer).map_err(|_| bad("the issuer is not a URL"))?;
    let scheme_ok = issuer.scheme() == "https" || (issuer.scheme() == "http" && loopback(&issuer));
    if !scheme_ok || issuer.host_str().is_none() {
        return Err(bad("the issuer must be an https:// URL"));
    }
    if !issuer.username().is_empty() || issuer.password().is_some() || issuer.fragment().is_some() {
        return Err(bad("the issuer carries credentials or a fragment"));
    }
    let audience = &document.audience;
    if audience.is_empty()
        || audience.len() > MAX_AUDIENCE_BYTES
        || audience.chars().any(char::is_control)
    {
        return Err(bad("the audience is not a short single-line identifier"));
    }
    Ok(())
}

/// A flag never overrides the document: one that differs from what the host publishes is an error.
fn merge(
    document: LoginDiscovery,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> Result<LoginDiscovery, CliError> {
    for (flag, published, name) in [
        (issuer, &document.issuer, "issuer"),
        (audience, &document.audience, "audience"),
    ] {
        if flag.is_some_and(|given| given != published) {
            return Err(config(format!(
                "--{name} differs from the {name} the host publishes"
            ))
            .with_hint("drop the flag, or check that you are signing in to the right host"));
        }
    }
    Ok(document)
}

/// Refuses to move a host to another issuer or audience behind the user's back.
fn check_known(store: &Store, host: &str, found: &LoginDiscovery) -> Result<(), CliError> {
    let stored = store.read()?;
    match stored.hosts.get(host) {
        Some(entry) if entry.issuer != found.issuer || entry.audience != found.audience => {
            Err(config(format!(
                "{host} is already signed in with a different issuer or audience"
            ))
            .with_hint(format!("sign out first: `weglarka --host {host} logout`")))
        }
        _ => Ok(()),
    }
}

/// Turns the arguments (and, unless both flags are given, the host's document) into what to sign
/// in with. Both flags: nothing is fetched, so older panels keep working.
pub(super) async fn resolve_target<T: Transport>(
    transport: &T,
    store: &Store,
    host: &str,
    args: &LoginArgs,
) -> Result<LoginTarget, CliError> {
    let issuer = args.issuer.as_deref().map(str::trim);
    let audience = args.audience.as_deref().map(str::trim);
    let found = match (issuer, audience) {
        (Some(issuer), Some(audience)) => LoginDiscovery {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        },
        _ => merge(fetch(transport, host).await?, issuer, audience)?,
    };
    check_known(store, host, &found)?;
    Ok(LoginTarget {
        host: host.to_owned(),
        issuer: found.issuer,
        audience: found.audience,
        client_id: args.client_id.clone(),
    })
}
