//! Cloudflare adapter (API v4).
//!
//! Needs an API token with `Zone:Read` and `DNS:Edit`, scoped to the zones Węglarka may certify — the
//! token can rewrite every record in those zones, so it must not be an account-wide key. The zone of a
//! record is found by walking the name's suffixes against `GET /zones?name=`: a token only lists the
//! zones it may see, so a name outside them is `ZoneNotFound` rather than a write to a stranger's zone.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use weglarka_core::secret_store::SecretValue;

use crate::http::{Base, Client, HttpError, Response};
use crate::name::{valid_record_name, valid_txt_value};
use crate::provider::{DnsError, DnsProvider, RecordHandle};

const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
const TIMEOUT: Duration = Duration::from_secs(30);
/// Challenge records live for seconds; 60 is the lowest TTL Cloudflare accepts outside Enterprise.
const TTL: u32 = 60;
/// Cloudflare error code for "record does not exist" on delete.
const RECORD_NOT_FOUND: i64 = 81044;
const MAX_MESSAGE: usize = 300;

pub struct Cloudflare {
    client: Client,
    token: String,
    /// zone name → zone id; zones do not move, so one lookup per zone per daemon run.
    zones: Mutex<HashMap<String, String>>,
}

impl fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cloudflare")
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    #[serde(default = "no_result", bound(deserialize = "T: Deserialize<'de>"))]
    result: Option<T>,
}

fn no_result<T>() -> Option<T> {
    None
}

#[derive(Deserialize)]
struct ApiMessage {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Zone {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    id: String,
}

/// Cloudflare ids are 32 lower-case hex characters. Checked before an id goes into a request path.
fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Cloudflare {
    /// `token` is the API token; surrounding whitespace (a trailing newline in a secret file) is trimmed.
    pub fn new(token: &SecretValue) -> Result<Self, DnsError> {
        Self::with_base_url(token, DEFAULT_BASE_URL)
    }

    /// Adapter against another API root — the tests use a loopback mock (plain `http://` is accepted
    /// for loopback only).
    pub fn with_base_url(token: &SecretValue, base_url: &str) -> Result<Self, DnsError> {
        let token = std::str::from_utf8(token.expose())
            .map_err(|_| HttpError::Token)?
            .trim()
            .to_owned();
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::Token.into());
        }
        Ok(Self {
            client: Client::new(Base::parse(base_url)?, TIMEOUT)?,
            token,
            zones: Mutex::new(HashMap::new()),
        })
    }

    async fn call(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Response, DnsError> {
        Ok(self.client.request(method, path, &self.token, body).await?)
    }

    /// Id of the zone that contains `name`: the longest suffix (at least two labels) the token can see.
    async fn zone_id(&self, name: &str) -> Result<String, DnsError> {
        let labels: Vec<&str> = name.split('.').collect();
        let candidates: Vec<String> = (0..labels.len().saturating_sub(1))
            .map(|start| labels[start..].join("."))
            .collect();
        {
            let cache = self.zones.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(id) = candidates.iter().find_map(|zone| cache.get(zone)) {
                return Ok(id.clone());
            }
        }
        for zone in candidates {
            let response = self
                .call("GET", &format!("/zones?name={zone}&per_page=1"), None)
                .await?;
            let zones: Vec<Zone> = parse(&response)?.unwrap_or_default();
            let Some(found) = zones.into_iter().find(|z| z.name == zone) else {
                continue;
            };
            if !valid_id(&found.id) {
                return Err(DnsError::Response("zone id has an unexpected shape".into()));
            }
            self.zones
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(zone, found.id.clone());
            return Ok(found.id);
        }
        Err(DnsError::ZoneNotFound(name.to_owned()))
    }
}

/// The `result` of a successful envelope; an unsuccessful one becomes [`DnsError::Api`] with the
/// provider's own error text (it never contains our request, so never the token).
fn parse<T: for<'de> Deserialize<'de>>(response: &Response) -> Result<Option<T>, DnsError> {
    let envelope: Result<Envelope<T>, _> = serde_json::from_slice(&response.body);
    let ok_status = (200..300).contains(&response.status);
    match envelope {
        Ok(envelope) if ok_status && envelope.success => Ok(envelope.result),
        Ok(envelope) => Err(api_error(response.status, &envelope.errors)),
        Err(_) if ok_status => Err(DnsError::Response("body is not the expected JSON".into())),
        Err(_) => Err(api_error(response.status, &[])),
    }
}

fn api_error(status: u16, errors: &[ApiMessage]) -> DnsError {
    let mut message = errors
        .iter()
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ");
    if message.is_empty() {
        message = "no error details".to_owned();
    }
    message.truncate(message.floor_char_boundary(MAX_MESSAGE));
    DnsError::Api { status, message }
}

impl DnsProvider for Cloudflare {
    async fn set_txt(&self, name: &str, value: &str) -> Result<RecordHandle, DnsError> {
        if !valid_record_name(name) {
            return Err(DnsError::InvalidName(name.to_owned()));
        }
        if !valid_txt_value(value) {
            return Err(DnsError::InvalidValue);
        }
        let zone = self.zone_id(name).await?;
        let body = json!({ "type": "TXT", "name": name, "content": value, "ttl": TTL });
        let body = serde_json::to_vec(&body).map_err(|e| DnsError::Response(e.to_string()))?;
        let response = self
            .call("POST", &format!("/zones/{zone}/dns_records"), Some(&body))
            .await?;
        let record: Record = parse(&response)?
            .ok_or_else(|| DnsError::Response("no record in the answer".into()))?;
        if !valid_id(&record.id) {
            return Err(DnsError::Response(
                "record id has an unexpected shape".into(),
            ));
        }
        tracing::debug!(%name, "published ACME TXT record");
        Ok(RecordHandle::new(format!("{zone}/{}", record.id)))
    }

    async fn remove_txt(&self, handle: &RecordHandle) -> Result<(), DnsError> {
        let (zone, record) = handle
            .as_str()
            .split_once('/')
            .filter(|(zone, record)| valid_id(zone) && valid_id(record))
            .ok_or_else(|| DnsError::InvalidHandle(handle.as_str().to_owned()))?;
        let response = self
            .call(
                "DELETE",
                &format!("/zones/{zone}/dns_records/{record}"),
                None,
            )
            .await?;
        // Already gone is success: cleanup also runs after a failed order, and may run twice.
        let gone = response.status == 404
            || serde_json::from_slice::<Envelope<serde_json::Value>>(&response.body)
                .is_ok_and(|e| e.errors.iter().any(|m| m.code == RECORD_NOT_FOUND));
        if gone {
            return Ok(());
        }
        parse::<serde_json::Value>(&response).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const ZONE: &str = "023e105f4ecef8ad9ca31a8372d0c353";
    const RECORD: &str = "372e67954025e0ba6aaa6d586b9e0b59";
    const TOKEN: &str = "s3cr3t-token-value";
    const VALUE: &str = "gfj9Xq-Ae1w0lBsJ4M2zQ8Yh7N3uKdR5vTpCoEiLxHk";

    /// Serves the canned `(status, body)` answers one connection each and records the raw requests.
    struct Mock {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl Mock {
        async fn serve(answers: Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::clone(&requests);
            tokio::spawn(async move {
                for (status, body) in answers {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 2048];
                    loop {
                        let n = stream.read(&mut chunk).await.unwrap();
                        raw.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&raw);
                        if let Some(end) = text.find("\r\n\r\n") {
                            let length = text
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length: "))
                                .map_or(0, |l| l.trim().parse::<usize>().unwrap());
                            if raw.len() >= end + 4 + length {
                                break;
                            }
                        }
                        assert!(n > 0, "client closed early");
                    }
                    log.lock().unwrap().push(String::from_utf8(raw).unwrap());
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(reply.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            Self { addr, requests }
        }

        fn adapter(&self) -> Cloudflare {
            let url = format!("http://{}/client/v4", self.addr);
            Cloudflare::with_base_url(&SecretValue::new(format!("{TOKEN}\n")), &url).unwrap()
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn ok(result: &str) -> (u16, String) {
        (
            200,
            format!(r#"{{"success":true,"errors":[],"result":{result}}}"#),
        )
    }

    fn zone_hit(name: &str) -> (u16, String) {
        ok(&format!(r#"[{{"id":"{ZONE}","name":"{name}"}}]"#))
    }

    #[tokio::test]
    async fn publishes_a_txt_record_in_the_longest_visible_zone() {
        let mock = Mock::serve(vec![
            ok("[]"), // _acme-challenge.example.eu is not a zone
            zone_hit("example.eu"),
            ok(&format!(r#"{{"id":"{RECORD}"}}"#)),
        ])
        .await;
        let handle = mock
            .adapter()
            .set_txt("_acme-challenge.example.eu", VALUE)
            .await
            .unwrap();
        assert_eq!(handle.as_str(), format!("{ZONE}/{RECORD}"));

        let requests = mock.requests();
        assert!(requests[0].starts_with(
            "GET /client/v4/zones?name=_acme-challenge.example.eu&per_page=1 HTTP/1.1\r\n"
        ));
        assert!(requests[1].starts_with("GET /client/v4/zones?name=example.eu&per_page=1 "));
        assert!(requests[2].starts_with(&format!(
            "POST /client/v4/zones/{ZONE}/dns_records HTTP/1.1\r\n"
        )));
        for request in &requests {
            assert!(request.contains(&format!("Authorization: Bearer {TOKEN}\r\n")));
        }
        let body: serde_json::Value =
            serde_json::from_str(requests[2].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(
            body,
            json!({"type":"TXT","name":"_acme-challenge.example.eu","content":VALUE,"ttl":60})
        );
    }

    #[tokio::test]
    async fn two_values_on_one_name_are_two_records_and_the_zone_is_cached() {
        let second = "4Mf1kQz8Yh7N3uKdR5vTpCoEiLxHkgfj9Xq-Ae1w0lB";
        let mock = Mock::serve(vec![
            zone_hit("example.eu"), // wildcard orders also publish for the apex name
            ok(&format!(r#"{{"id":"{RECORD}"}}"#)),
            ok(&format!(r#"{{"id":"{ZONE}"}}"#)),
        ])
        .await;
        let cf = mock.adapter();
        let a = cf.set_txt("example.eu", VALUE).await.unwrap();
        let b = cf.set_txt("example.eu", second).await.unwrap();
        assert_ne!(a, b);
        assert_eq!(
            mock.requests().len(),
            3,
            "the second call skips the zone lookup"
        );
    }

    #[tokio::test]
    async fn removes_the_exact_record_and_tolerates_a_missing_one() {
        let gone = (
            404,
            r#"{"success":false,"errors":[{"code":81044,"message":"Record does not exist."}]}"#
                .to_owned(),
        );
        let mock = Mock::serve(vec![ok(&format!(r#"{{"id":"{RECORD}"}}"#)), gone]).await;
        let cf = mock.adapter();
        let handle = RecordHandle::new(format!("{ZONE}/{RECORD}"));
        cf.remove_txt(&handle).await.unwrap();
        cf.remove_txt(&handle).await.unwrap();
        let requests = mock.requests();
        assert!(requests[0].starts_with(&format!(
            "DELETE /client/v4/zones/{ZONE}/dns_records/{RECORD} HTTP/1.1\r\n"
        )));
        assert!(!requests[0].contains("Content-Length"));
    }

    #[tokio::test]
    async fn a_name_outside_the_visible_zones_is_not_written() {
        let mock = Mock::serve(vec![ok("[]"), ok("[]")]).await;
        let err = mock
            .adapter()
            .set_txt("_acme-challenge.nope.eu", VALUE)
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::ZoneNotFound(name) if name == "_acme-challenge.nope.eu"));
        assert_eq!(mock.requests().len(), 2, "no POST after the lookups");
    }

    #[tokio::test]
    async fn api_errors_carry_the_provider_text_but_never_the_token() {
        let denied = (
            403,
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}"#
                .to_owned(),
        );
        let mock = Mock::serve(vec![denied]).await;
        let err = mock
            .adapter()
            .set_txt("example.eu", VALUE)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("HTTP 403") && text.contains("9109: Invalid access token"),
            "{text}"
        );
        assert!(!text.contains(TOKEN) && !format!("{err:?}").contains(TOKEN));
    }

    #[tokio::test]
    async fn malformed_answers_are_errors() {
        let mock = Mock::serve(vec![
            (200, "<html>".to_owned()),
            ok(r#"[{"id":"../../etc","name":"example.eu"}]"#),
            zone_hit("example.eu"),
            ok(r#"{"id":"nope"}"#),
            (502, "bad gateway".to_owned()),
        ])
        .await;
        let cf = mock.adapter();
        assert!(matches!(
            cf.set_txt("example.eu", VALUE).await,
            Err(DnsError::Response(_))
        ));
        assert!(matches!(
            cf.set_txt("example.eu", VALUE).await,
            Err(DnsError::Response(_))
        ));
        assert!(matches!(
            cf.set_txt("example.eu", VALUE).await,
            Err(DnsError::Response(_))
        ));
        let err = cf
            .remove_txt(&RecordHandle::new(format!("{ZONE}/{RECORD}")))
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::Api { status: 502, .. }));
    }

    #[tokio::test]
    async fn bad_input_never_reaches_the_network() {
        let mock = Mock::serve(vec![]).await;
        let cf = mock.adapter();
        for name in ["example", "Example.eu", "a/b.eu", "*.example.eu", ""] {
            assert!(matches!(
                cf.set_txt(name, VALUE).await,
                Err(DnsError::InvalidName(_))
            ));
        }
        assert!(matches!(
            cf.set_txt("example.eu", "a b").await,
            Err(DnsError::InvalidValue)
        ));
        for handle in [
            "",
            "x",
            "../a/b",
            &format!("{ZONE}/{RECORD}/x"),
            &format!("{ZONE}/.."),
        ] {
            let err = cf.remove_txt(&RecordHandle::new(handle)).await.unwrap_err();
            assert!(matches!(err, DnsError::InvalidHandle(_)), "{handle}");
        }
        assert!(mock.requests().is_empty());
    }

    #[test]
    fn tokens_are_validated_and_redacted() {
        let url = "http://127.0.0.1:1";
        for bad in ["", "  \n", "has space", "\u{e4}"] {
            assert!(
                Cloudflare::with_base_url(&SecretValue::new(bad), url).is_err(),
                "{bad:?}"
            );
        }
        assert!(Cloudflare::with_base_url(&SecretValue::new(vec![0xff]), url).is_err());
        let cf = Cloudflare::with_base_url(&SecretValue::new(TOKEN), url).unwrap();
        assert!(!format!("{cf:?}").contains(TOKEN));
        assert!(Cloudflare::new(&SecretValue::new(TOKEN)).is_ok());
        assert!(Cloudflare::with_base_url(&SecretValue::new(TOKEN), "http://example.eu").is_err());
    }
}
