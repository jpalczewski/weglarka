//! The device authorization grant (RFC 8628), the transport-independent half.

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use crate::token::{ClientAuth, TokenSet, parse_tokens, signed_form};
use crate::{Error, MAX_BODY, Secret, Transport, status_error};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
const MIN_INTERVAL: Duration = Duration::from_secs(1);
const MAX_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_LIFETIME: Duration = Duration::from_secs(10 * 60);
const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// RFC 8628 3.5: each `slow_down` adds this much to the polling interval.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// A started device login: show `user_code` and the verification URI, then poll.
pub struct DeviceAuthorization {
    pub device_code: Secret,
    pub user_code: String,
    pub verification_uri: Url,
    /// The URI with the code filled in, when the provider offers it.
    pub verification_uri_complete: Option<Url>,
    pub expires_in: Duration,
    pub interval: Duration,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceAuthorization(<redacted>)")
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawDevice {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
    interval: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawError {
    error: String,
}

/// What one poll of the token endpoint said.
#[derive(Debug)]
pub enum DevicePoll {
    /// The person approved.
    Approved(TokenSet),
    /// Not yet; ask again after the (possibly lengthened) `interval`.
    Pending { interval: Duration },
    /// The person said no.
    Denied,
    /// The device code lapsed.
    Expired,
}

/// Step 1: asks for a device code and a user code.
pub async fn device_authorization<T: Transport>(
    transport: &T,
    endpoint: &Url,
    client_id: &str,
    scope: &str,
    audience: &str,
) -> Result<DeviceAuthorization, Error> {
    let (header, body) = signed_form(
        ClientAuth::Public { id: client_id },
        &[("scope", scope), ("audience", audience)],
    )?;
    let response = transport
        .post_form(endpoint, header.as_ref(), body, MAX_BODY)
        .await?;
    if !(200..300).contains(&response.status) {
        return Err(status_error(response.status));
    }
    let raw: RawDevice = serde_json::from_slice(&response.body)
        .map_err(|_| Error::BadResponse("the device authorization response is not JSON"))?;
    if raw.device_code.is_empty() || raw.user_code.is_empty() {
        return Err(Error::BadResponse("no device code or user code"));
    }
    let uri = |raw: &str| {
        Url::parse(raw)
            .ok()
            .filter(|u| u.scheme() == "https" || crate::loopback_http(u))
            .ok_or(Error::BadResponse("the verification URI is not https"))
    };
    Ok(DeviceAuthorization {
        device_code: Secret::new(raw.device_code),
        user_code: raw.user_code,
        verification_uri: uri(&raw.verification_uri)?,
        verification_uri_complete: raw
            .verification_uri_complete
            .as_deref()
            .map(uri)
            .transpose()?,
        expires_in: raw.expires_in.map_or(DEFAULT_LIFETIME, |s| {
            Duration::from_secs(s).min(MAX_LIFETIME)
        }),
        interval: raw.interval.map_or(DEFAULT_INTERVAL, |s| {
            Duration::from_secs(s).clamp(MIN_INTERVAL, MAX_INTERVAL)
        }),
    })
}

/// Step 2: one poll. `interval` is the current polling interval, returned (lengthened after
/// `slow_down`) in [`DevicePoll::Pending`].
pub async fn poll_device_token<T: Transport>(
    transport: &T,
    endpoint: &Url,
    client_id: &str,
    device_code: &Secret,
    interval: Duration,
) -> Result<DevicePoll, Error> {
    let (header, body) = signed_form(
        ClientAuth::Public { id: client_id },
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.expose()),
        ],
    )?;
    let response = transport
        .post_form(endpoint, header.as_ref(), body, MAX_BODY)
        .await?;
    if (200..300).contains(&response.status) {
        return parse_tokens(&response.body).map(DevicePoll::Approved);
    }
    if response.status == 400 {
        let raw: RawError = serde_json::from_slice(&response.body).unwrap_or_default();
        return match raw.error.as_str() {
            "authorization_pending" => Ok(DevicePoll::Pending { interval }),
            "slow_down" => Ok(DevicePoll::Pending {
                interval: (interval + SLOW_DOWN_STEP).min(MAX_INTERVAL),
            }),
            "access_denied" => Ok(DevicePoll::Denied),
            "expired_token" => Ok(DevicePoll::Expired),
            _ => Err(status_error(400)),
        };
    }
    Err(status_error(response.status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Script;

    fn endpoint() -> Url {
        Url::parse("https://auth.example.com/device").unwrap()
    }

    #[tokio::test]
    async fn starts_a_login_and_clamps_the_provider_numbers() {
        let script = Script::default();
        script.push(
            200,
            r#"{"device_code":"dc","user_code":"ABCD-1234","verification_uri":"https://auth.example.com/device","expires_in":99999,"interval":0}"#,
        );
        let d = device_authorization(
            &script,
            &endpoint(),
            "cli",
            "openid",
            "https://admin.example.com/api/",
        )
        .await
        .unwrap();
        assert_eq!(d.user_code, "ABCD-1234");
        assert_eq!(d.expires_in, MAX_LIFETIME);
        assert_eq!(d.interval, MIN_INTERVAL);
        assert_eq!(
            script.seen.lock().unwrap()[0].2,
            "client_id=cli&scope=openid&audience=https%3A%2F%2Fadmin.example.com%2Fapi%2F"
        );
    }

    #[tokio::test]
    async fn refuses_a_verification_uri_that_is_not_https() {
        let script = Script::default();
        script.push(
            200,
            r#"{"device_code":"dc","user_code":"X","verification_uri":"http://evil.example.org/d"}"#,
        );
        assert!(matches!(
            device_authorization(&script, &endpoint(), "cli", "openid", "a").await,
            Err(Error::BadResponse(_))
        ));
    }

    #[tokio::test]
    async fn polls_through_pending_slow_down_denied_expired_and_approval() {
        let script = Script::default();
        script.push(400, r#"{"error":"authorization_pending"}"#);
        script.push(400, r#"{"error":"slow_down"}"#);
        script.push(400, r#"{"error":"access_denied"}"#);
        script.push(400, r#"{"error":"expired_token"}"#);
        script.push(400, r#"{"error":"invalid_client"}"#);
        script.push(
            200,
            r#"{"access_token":"a","token_type":"Bearer","refresh_token":"r"}"#,
        );
        let code = Secret::new("dc");
        let url = endpoint();
        let poll = |i| poll_device_token(&script, &url, "cli", &code, i);
        let five = Duration::from_secs(5);
        assert!(
            matches!(poll(five).await.unwrap(), DevicePoll::Pending { interval } if interval == five)
        );
        assert!(
            matches!(poll(five).await.unwrap(), DevicePoll::Pending { interval } if interval == Duration::from_secs(10))
        );
        assert!(matches!(poll(five).await.unwrap(), DevicePoll::Denied));
        assert!(matches!(poll(five).await.unwrap(), DevicePoll::Expired));
        assert!(matches!(poll(five).await, Err(Error::Refused(400))));
        let DevicePoll::Approved(tokens) = poll(five).await.unwrap() else {
            panic!("expected approval");
        };
        assert_eq!(tokens.refresh.unwrap().expose(), "r");
        assert!(script.seen.lock().unwrap()[0].2.contains("device_code=dc"));
    }
}
