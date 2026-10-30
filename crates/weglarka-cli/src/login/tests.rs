//! `login`, token refresh and `logout` against a scripted provider.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use weglarka_oidc::{Error, HttpResponse, Url};

use super::*;

const HOST: &str = "https://panel.example.com";

#[derive(Default)]
struct Provider {
    answers: Mutex<VecDeque<Result<HttpResponse, Error>>>,
    seen: Mutex<Vec<(String, String)>>,
}

impl Provider {
    fn say(&self, status: u16, body: &str) -> &Self {
        self.answers.lock().unwrap().push_back(Ok(HttpResponse {
            status,
            body: body.as_bytes().to_vec(),
        }));
        self
    }

    fn fail(&self) -> &Self {
        self.answers
            .lock()
            .unwrap()
            .push_back(Err(Error::Network("down".into())));
        self
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }

    fn next(&self, url: &Url, body: String) -> Result<HttpResponse, Error> {
        self.seen.lock().unwrap().push((url.to_string(), body));
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("the provider was asked more than the test scripted")
    }
}

impl Transport for Provider {
    async fn get(&self, url: &Url, _limit: usize) -> Result<HttpResponse, Error> {
        self.next(url, String::new())
    }

    async fn post_form(
        &self,
        url: &Url,
        _authorization: Option<&Secret>,
        body: String,
        _limit: usize,
    ) -> Result<HttpResponse, Error> {
        self.next(url, body)
    }
}

fn discovery(device: bool, revocation: bool) -> String {
    let mut doc = serde_json::json!({
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "jwks_uri": "https://auth.example.com/jwks.json",
    });
    if device {
        doc["device_authorization_endpoint"] = "https://auth.example.com/device".into();
    }
    if revocation {
        doc["revocation_endpoint"] = "https://auth.example.com/revoke".into();
    }
    doc.to_string()
}

const DEVICE: &str = r#"{"device_code":"DEVCODE","user_code":"ABCD-1234","verification_uri":"https://auth.example.com/device","expires_in":600,"interval":5}"#;
const TOKENS: &str = r#"{"access_token":"ACCESS1","token_type":"Bearer","expires_in":900,"refresh_token":"REFRESH1"}"#;

fn request() -> LoginRequest {
    LoginRequest {
        host: HOST.into(),
        issuer: "https://auth.example.com".into(),
        audience: "https://admin.example.com/api/".into(),
        client_id: "weglarka-cli".into(),
    }
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("credentials.toml"));
    (dir, store)
}

fn signed_in(store: &Store, expires: u64, refresh: Option<&str>) {
    store
        .update(|c| {
            c.hosts.insert(
                HOST.into(),
                HostEntry {
                    issuer: "https://auth.example.com".into(),
                    client_id: "weglarka-cli".into(),
                    audience: "https://admin.example.com/api/".into(),
                    access_token: "OLDACCESS".into(),
                    access_expires: expires,
                    refresh_token: refresh.map(str::to_owned),
                },
            );
        })
        .unwrap();
}

async fn no_wait(_: Duration) {}

async fn run_login(provider: &Provider, store: &Store) -> Result<Session, CliError> {
    device_login(provider, store, &request(), 1_000, no_wait, |_| {}).await
}

#[tokio::test]
async fn login_waits_through_pending_and_stores_the_tokens() {
    let provider = Provider::default();
    provider
        .say(200, &discovery(true, false))
        .say(200, DEVICE)
        .say(400, r#"{"error":"authorization_pending"}"#)
        .say(400, r#"{"error":"slow_down"}"#)
        .say(200, TOKENS);
    let (_dir, store) = store();
    let waits = Mutex::new(Vec::new());
    let shown = Mutex::new(String::new());
    let session = device_login(
        &provider,
        &store,
        &request(),
        1_000,
        |d| {
            waits.lock().unwrap().push(d.as_secs());
            async {}
        },
        |d| *shown.lock().unwrap() = format!("{} {}", d.user_code, d.verification_uri),
    )
    .await
    .unwrap();

    assert_eq!(session.expires_in_secs, 900);
    assert!(session.refreshable);
    // The first poll waits the advertised interval, `slow_down` lengthens it by five seconds.
    assert_eq!(*waits.lock().unwrap(), [5, 5, 10]);
    assert_eq!(
        *shown.lock().unwrap(),
        "ABCD-1234 https://auth.example.com/device"
    );
    let entry = store.read().unwrap().hosts.remove(HOST).unwrap();
    assert_eq!(entry.access_token, "ACCESS1");
    // Issued after the 5 + 5 + 10 s of waiting, not when the login started.
    assert_eq!(entry.access_expires, 1_920);
    assert_eq!(entry.refresh_token.as_deref(), Some("REFRESH1"));
    // The device request is public (client_id, no secret) and names the audience.
    let requests = provider.requests();
    assert!(
        requests[1]
            .1
            .starts_with("client_id=weglarka-cli&scope=openid")
    );
    assert!(
        requests[1]
            .1
            .contains("audience=https%3A%2F%2Fadmin.example.com%2Fapi%2F")
    );
    assert!(requests[2].1.contains("device_code=DEVCODE"));
}

#[tokio::test]
async fn login_failures_leave_nothing_on_disk() {
    for (script, needle) in [
        (
            vec![(200, discovery(false, false))],
            "device authorization grant",
        ),
        (
            vec![
                (200, discovery(true, false)),
                (200, DEVICE.to_owned()),
                (400, r#"{"error":"access_denied"}"#.to_owned()),
            ],
            "denied",
        ),
        (
            vec![
                (200, discovery(true, false)),
                (200, DEVICE.to_owned()),
                (400, r#"{"error":"expired_token"}"#.to_owned()),
            ],
            "expired",
        ),
        (
            vec![(200, discovery(true, false)), (400, "{}".to_owned())],
            "refused the sign-in request",
        ),
    ] {
        let provider = Provider::default();
        for (status, body) in script {
            provider.say(status, &body);
        }
        let (_dir, store) = store();
        let err = run_login(&provider, &store).await.unwrap_err();
        assert!(err.message.contains(needle), "{}: {}", needle, err.message);
        assert!(store.read().unwrap().hosts.is_empty());
    }
}

#[tokio::test]
async fn login_gives_up_when_the_code_lapses_while_pending() {
    let provider = Provider::default();
    provider.say(200, &discovery(true, false)).say(
        200,
        r#"{"device_code":"D","user_code":"U","verification_uri":"https://auth.example.com/device","expires_in":10,"interval":5}"#,
    );
    provider
        .say(400, r#"{"error":"authorization_pending"}"#)
        .say(400, r#"{"error":"authorization_pending"}"#);
    let (_dir, store) = store();
    let err = run_login(&provider, &store).await.unwrap_err();
    assert!(err.message.contains("expired"));
}

#[tokio::test]
async fn a_token_with_time_left_is_used_without_touching_the_provider() {
    let (_dir, store) = store();
    signed_in(&store, 5_000, Some("R"));
    let provider = Provider::default();
    let (token, session) = access_token(&provider, &store, HOST, 1_000).await.unwrap();
    assert_eq!(token.expose(), "OLDACCESS");
    assert_eq!(session.expires_in_secs, 4_000);
    assert!(provider.requests().is_empty());
}

#[tokio::test]
async fn an_expiring_token_is_refreshed_and_the_rotated_refresh_token_kept() {
    let (_dir, store) = store();
    signed_in(&store, 1_030, Some("REFRESH0")); // inside the 60 s skew
    let provider = Provider::default();
    provider.say(200, &discovery(true, false)).say(
        200,
        r#"{"access_token":"ACCESS2","token_type":"Bearer","expires_in":900,"refresh_token":"REFRESH2"}"#,
    );
    let (token, _) = access_token(&provider, &store, HOST, 1_000).await.unwrap();
    assert_eq!(token.expose(), "ACCESS2");
    let entry = store.read().unwrap().hosts.remove(HOST).unwrap();
    assert_eq!(entry.access_token, "ACCESS2");
    assert_eq!(entry.access_expires, 1_900);
    assert_eq!(entry.refresh_token.as_deref(), Some("REFRESH2"));
    let body = &provider.requests()[1].1;
    assert!(body.contains("grant_type=refresh_token") && body.contains("refresh_token=REFRESH0"));
}

#[tokio::test]
async fn a_refresh_the_provider_refuses_ends_the_session_but_an_outage_does_not() {
    let (_dir, store) = store();
    signed_in(&store, 0, Some("REFRESH0"));
    let provider = Provider::default();
    provider.say(200, &discovery(true, false)).fail();
    let err = access_token(&provider, &store, HOST, 1_000)
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::Unreachable);
    assert!(
        store.read().unwrap().hosts.contains_key(HOST),
        "an outage must keep the tokens"
    );

    let provider = Provider::default();
    provider
        .say(200, &discovery(true, false))
        .say(400, r#"{"error":"invalid_grant"}"#);
    let err = access_token(&provider, &store, HOST, 1_000)
        .await
        .unwrap_err();
    assert!(err.message.contains("has ended"));
    assert!(store.read().unwrap().hosts.is_empty());

    // No refresh token at all: nothing to try.
    signed_in(&store, 0, None);
    let err = access_token(&Provider::default(), &store, HOST, 1_000)
        .await
        .unwrap_err();
    assert!(err.message.contains("has ended"));
    assert!(store.read().unwrap().hosts.is_empty());
}

#[tokio::test]
async fn logout_removes_the_tokens_first_and_asks_the_provider_to_revoke() {
    let (_dir, store) = store();
    signed_in(&store, 5_000, Some("REFRESH0"));
    let provider = Provider::default();
    provider.say(200, &discovery(true, true)).say(200, "");
    let out = sign_out(&provider, &store, HOST).await.unwrap();
    assert!(out.revoked);
    assert!(store.read().unwrap().hosts.is_empty());
    let revoke = &provider.requests()[1];
    assert_eq!(revoke.0, "https://auth.example.com/revoke");
    assert!(
        revoke.1.contains("token=REFRESH0") && revoke.1.contains("token_type_hint=refresh_token")
    );

    // A provider that is down still leaves the workstation clean.
    signed_in(&store, 5_000, Some("REFRESH0"));
    let provider = Provider::default();
    provider.fail();
    let out = sign_out(&provider, &store, HOST).await.unwrap();
    assert!(!out.revoked);
    assert!(store.read().unwrap().hosts.is_empty());

    let err = sign_out(&Provider::default(), &store, HOST)
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::NotFound);
}

#[test]
fn the_host_defaults_to_the_only_one_signed_in() {
    let (_dir, store) = store();
    assert_eq!(resolve_host(None, &store).unwrap_err().kind, Kind::NotFound);
    signed_in(&store, 1, None);
    assert_eq!(resolve_host(None, &store).unwrap(), HOST);
    assert_eq!(
        resolve_host(Some("https://Other.example.com/"), &store).unwrap(),
        "https://other.example.com"
    );
    store
        .update(|c| {
            let entry = c.hosts.remove(HOST).unwrap();
            c.hosts.insert("https://a.example.com".into(), entry);
            c.hosts.insert(
                "https://b.example.com".into(),
                HostEntry {
                    issuer: String::new(),
                    client_id: String::new(),
                    audience: String::new(),
                    access_token: String::new(),
                    access_expires: 0,
                    refresh_token: None,
                },
            );
        })
        .unwrap();
    let err = resolve_host(None, &store).unwrap_err();
    assert_eq!(err.kind, Kind::Usage);
    assert!(err.hint.unwrap().contains("a.example.com"));
}

#[tokio::test]
async fn nothing_secret_reaches_an_error_message() {
    let (_dir, store) = store();
    signed_in(&store, 0, Some("REFRESH-SECRET"));
    let provider = Provider::default();
    provider
        .say(200, &discovery(true, false))
        .say(503, r#"{"refresh_token":"REFRESH-SECRET"}"#);
    let err = access_token(&provider, &store, HOST, 1_000)
        .await
        .unwrap_err();
    let shown = format!("{err} {:?} {:?}", err.hint, err);
    assert!(!shown.contains("REFRESH-SECRET") && !shown.contains("OLDACCESS"));
    // Counted so the helper above is not optimised into never failing.
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 0);
}
