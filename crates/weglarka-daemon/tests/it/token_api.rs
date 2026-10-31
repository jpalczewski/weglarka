//! The token admin listener end to end (ADR 0056): the unix socket stays unauthenticated, the token
//! socket needs a bearer whose groups map to `read`/`admin`, and the provider's JWKS is fetched over
//! the ingress probe socket (served here by a stand-in).

use crate::common::*;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use weglarka_api::{Body, ENDPOINTS, Method};
use weglarka_model::admin_auth::Scope;
use weglarka_model::admin_auth::testing::{AUDIENCE, ISSUER, TestIssuer};

const SECTIONS: &str = r#"
[identity]
provider = "authelia"
instance = "authelia"
issuer = "https://auth.example.com"

[admin.http]
clients = ["panel"]
audience = "https://admin.example.com/api/"
read_groups = ["viewers"]
admin_groups = ["admins"]
"#;

pub(crate) struct Setup {
    pub(crate) h: Harness,
    pub(crate) issuer: TestIssuer,
    pub(crate) token_socket: PathBuf,
    pub(crate) jwks_fetches: Arc<AtomicUsize>,
}

/// Stands in for nginx's probe socket: answers every request with the JWKS and counts them. The
/// ingress manager owns that directory and may clear the socket while it applies, so the stand-in
/// binds it again whenever it is gone.
fn serve_jwks(socket: PathBuf, jwks: String) -> Arc<AtomicUsize> {
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    tokio::spawn(async move {
        let mut listener: Option<UnixListener> = None;
        loop {
            if listener.is_none() || !socket.exists() {
                if let Some(dir) = socket.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::remove_file(&socket);
                listener = UnixListener::bind(&socket).ok();
            }
            let Some(l) = &listener else {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            };
            let accepted =
                tokio::time::timeout(std::time::Duration::from_millis(10), l.accept()).await;
            let Ok(Ok((mut stream, _))) = accepted else {
                continue;
            };
            let (jwks, counter) = (jwks.clone(), counter.clone());
            tokio::spawn(async move {
                let mut request = vec![0u8; 2048];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]).into_owned();
                if request.starts_with("GET /jwks.json ")
                    && request.contains("\r\nHost: auth.example.com\r\n")
                {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{jwks}",
                                jwks.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                        .await;
                }
            });
        }
    });
    fetches
}

pub(crate) async fn setup() -> Setup {
    let h = Builder::new().sections(SECTIONS).build().await;
    let issuer = TestIssuer::new("k1");
    let probe = weglarka_daemon::ingress::probe_socket_path(&h.root.join("state/nginx"));
    let jwks_fetches = serve_jwks(probe, issuer.jwks_json());
    let token_socket = h
        .running
        .admin_token_socket
        .clone()
        .expect("[admin.http] starts the token listener");
    Setup {
        h,
        issuer,
        token_socket,
        jwks_fetches,
    }
}

pub(crate) async fn call(
    socket: &PathBuf,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, hyper::HeaderMap, Value) {
    let stream = UnixStream::connect(socket).await.unwrap();
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req
        .body(Full::new(Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, headers, value)
}

/// `/v1/apps/{name}` → `/v1/apps/x`: a request that reaches the handler of that route.
fn concrete(template: &str) -> String {
    let mut out = String::new();
    let mut in_param = false;
    for c in template.chars() {
        match c {
            '{' => {
                in_param = true;
                out.push('x');
            }
            '}' => in_param = false,
            _ if !in_param => out.push(c),
            _ => {}
        }
    }
    out
}

#[tokio::test]
async fn the_token_socket_demands_a_valid_bearer_and_only_health_is_open() {
    let s = setup().await;
    let sock = &s.token_socket;

    let (status, headers, body) = call(sock, "GET", "/v1/health", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.get("www-authenticate").is_none());

    for token in [None, Some("garbage"), Some("a.b.c")] {
        let (status, headers, body) = call(sock, "GET", "/v1/apps", token, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?} {body}");
        assert_eq!(headers["www-authenticate"], "Bearer");
        assert_eq!(body["code"], "unauthorized");
    }
    // An unknown path does not leak that it is unknown to someone without a token.
    let (status, ..) = call(sock, "GET", "/v1/nope", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A token for another audience, one signed by a stranger, one without a mapped group.
    let wrong_aud = s.issuer.sign(&json!({
        "iss": ISSUER, "aud": "https://elsewhere.example.com", "sub": "a",
        "exp": 4_000_000_000u64, "groups": ["admins"]
    }));
    let stranger = TestIssuer::new("k1").token("a", &["admins"]);
    for token in [wrong_aud, stranger] {
        let (status, ..) = call(sock, "GET", "/v1/apps", Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // A genuine token whose groups map to no scope is authenticated but not authorized: 403.
    let no_group = s.issuer.token("a", &["interns"]);
    let (status, _, body) = call(sock, "GET", "/v1/apps", Some(&no_group), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "forbidden");
}

#[tokio::test]
async fn scopes_decide_what_a_token_may_do() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    let admin_token = s.issuer.token("adam", &["admins"]);

    let (status, _, body) = call(sock, "GET", "/v1/apps", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = call(
        sock,
        "POST",
        "/v1/apps",
        Some(&reader),
        Some(json!({"name": "x", "spec": spec("x.example.com")})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "forbidden");

    let (status, _, body) = call(
        sock,
        "POST",
        "/v1/apps",
        Some(&admin_token),
        Some(json!({"name": "x", "spec": spec("x.example.com")})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The change is the daemon's, whichever door it came through.
    let (status, body) = admin(&s.h, "GET", "/v1/apps/x", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `admin` includes `read`.
    let (status, ..) = call(sock, "GET", "/v1/apps/x", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // One JWKS fetch served every request above.
    assert_eq!(s.jwks_fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_read_token_sees_env_keys_without_values_and_the_runtime_detail() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    let admin_token = s.issuer.token("adam", &["admins"]);

    let mut app = spec("x.example.com");
    app["env"] = json!({ "DATABASE_URL": "postgres://u:hunter2@db/x", "MODE": "prod" });
    add(&s.h, "x", app).await;
    deployed(&s.h, "x").await;

    // Read scope: the keys, never the values — and nothing of them anywhere in the answer.
    let (status, _, body) = call(sock, "GET", "/v1/apps/x", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["spec"]["env"],
        json!({ "DATABASE_URL": "", "MODE": "" })
    );
    assert!(!body.to_string().contains("hunter2"), "{body}");
    // The runtime detail is there for the panel.
    assert_eq!(body["restarts"], 0, "{body}");
    assert!(body["started_at"].is_string(), "{body}");

    // Admin scope and the unix socket keep the real values.
    let (status, _, body) = call(sock, "GET", "/v1/apps/x", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["spec"]["env"]["DATABASE_URL"],
        "postgres://u:hunter2@db/x"
    );
    let body = show(&s.h, "x").await;
    assert_eq!(
        body["spec"]["env"]["DATABASE_URL"],
        "postgres://u:hunter2@db/x"
    );
    assert_eq!(body["spec"]["env"]["MODE"], "prod");
    assert_eq!(body["restarts"], 0, "{body}");
}

#[tokio::test]
async fn a_read_token_does_not_see_argv_or_failure_text() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    let admin_token = s.issuer.token("adam", &["admins"]);

    let mut app = spec("y.example.com");
    app["command"] = json!(["serve", "--password=hunter2"]);
    add(&s.h, "y", app).await;
    deployed(&s.h, "y").await;

    // The probes would need a real container and ingress to pass the deploy gate, so they are
    // declared on the stored spec afterwards.
    let apps_path = s.h.root.join("state/apps.toml");
    let mut apps = weglarka_model::state::load_apps(&apps_path).unwrap();
    let name = weglarka_model::app::InstanceName::new("y").unwrap();
    let health = &mut apps.apps.get_mut(&name).expect("spec of y").health;
    health.command = Some(vec!["check".into(), "--token=t0k3n".into()]);
    health.http = Some(weglarka_model::app::HttpProbe {
        path: "/ready?key=s3cret".into(),
        ..Default::default()
    });
    weglarka_model::state::save_apps(&apps_path, &apps).unwrap();

    // The engine records a failed deploy with free-form text.
    let state_path = s.h.root.join("state/state.toml");
    let mut st = weglarka_model::state::load_state(&state_path).unwrap();
    let entry = st.apps.get_mut(&name).expect("state of y");
    let digest = entry.current.clone().expect("current digest");
    entry.failed = Some(weglarka_model::state::FailedDeploy {
        digest: digest.clone(),
        reason: "pull failed: password=hunter2".into(),
    });
    weglarka_model::state::save_state(&state_path, &st).unwrap();

    let (status, _, body) = call(sock, "GET", "/v1/apps/y", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["spec"]["command"],
        json!(["<redacted>", "<redacted>"]),
        "{body}"
    );
    assert_eq!(
        body["spec"]["health"]["command"],
        json!(["<redacted>", "<redacted>"])
    );
    assert_eq!(body["spec"]["health"]["http"]["path"], "/ready");
    assert_eq!(body["state"]["failed"]["digest"], json!(digest), "{body}");
    assert_eq!(
        body["state"]["failed"]["reason"],
        "deploy failed (details withheld)"
    );
    let text = body.to_string();
    for secret in ["hunter2", "t0k3n", "s3cret"] {
        assert!(!text.contains(secret), "{secret} leaked: {body}");
    }

    let (status, _, body) = call(sock, "GET", "/v1/apps/y", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["spec"]["command"][1], "--password=hunter2");
    assert_eq!(body["spec"]["health"]["command"][1], "--token=t0k3n");
    assert_eq!(body["spec"]["health"]["http"]["path"], "/ready?key=s3cret");
    assert_eq!(
        body["state"]["failed"]["reason"],
        "pull failed: password=hunter2"
    );
    let body = show(&s.h, "y").await;
    assert_eq!(body["spec"]["command"][1], "--password=hunter2");
}

#[tokio::test]
async fn every_declared_endpoint_is_routed_and_enforces_its_scope() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    for e in ENDPOINTS {
        let method = e.method.as_str();
        let path = concrete(e.path);
        let (status, _, body) = call(sock, method, &path, Some(&reader), None).await;
        let what = format!("{method} {} -> {status} {body}", e.path);
        match e.scope {
            None => {}
            Some(Scope::Admin) => assert_eq!(status, StatusCode::FORBIDDEN, "{what}"),
            Some(Scope::Read) => {
                assert!(
                    status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
                    "{what}"
                );
                // Routed: the handler answered, not the router's fallback.
                assert_ne!(body["message"], "no such endpoint", "{what}");
            }
        }
        // And without any token everything but health is refused.
        let (status, ..) = call(sock, method, &path, None, None).await;
        let open = e.scope.is_none();
        assert_eq!(status != StatusCode::UNAUTHORIZED, open, "{}", e.path);
    }
}

/// Every endpoint the table declares as answering with app data hands a `read` token the redacted
/// view, and an `admin` token the stored one (issue #255). An `AppView` endpoint above `read` is
/// refused outright.
#[tokio::test]
async fn every_app_view_endpoint_answers_read_with_the_redacted_view() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    let admin_token = s.issuer.token("adam", &["admins"]);

    let mut app = spec("w.example.com");
    app["env"] = json!({ "DATABASE_URL": "postgres://u:hunter2@db/w" });
    let mut walked = 0;
    for e in ENDPOINTS.iter().filter(|e| e.body == Body::AppView) {
        let method = e.method.as_str();
        let path = match e.path {
            "/v1/apps" => "/v1/apps".to_owned(),
            _ => "/v1/apps/w".to_owned(),
        };
        let body = match e.method {
            Method::Post => Some(json!({ "name": "w", "spec": app })),
            Method::Put => Some(json!({ "spec": app })),
            _ => None,
        };
        let what = format!("{method} {}", e.path);

        // The view sits in `app` when the answer wraps it (update).
        let view = |body: &Value| body.get("app").unwrap_or(body).clone();

        let (status, _, answer) = call(sock, method, &path, Some(&reader), body.clone()).await;
        match e.scope {
            Some(Scope::Read) => {
                assert_eq!(status, StatusCode::OK, "{what}: {answer}");
                let v = view(&answer);
                assert_eq!(v["redacted"], true, "{what}: {answer}");
                assert!(v.get("reconciled").is_none(), "{what}: {answer}");
                assert!(!answer.to_string().contains("hunter2"), "{what}: {answer}");
            }
            _ => assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {answer}"),
        }

        let (status, _, answer) = call(sock, method, &path, Some(&admin_token), body).await;
        assert_eq!(status, StatusCode::OK, "{what}: {answer}");
        let v = view(&answer);
        assert!(v.get("redacted").is_none(), "{what}: {answer}");
        assert_eq!(
            v["spec"]["env"]["DATABASE_URL"], "postgres://u:hunter2@db/w",
            "{what}: {answer}"
        );
        walked += 1;
    }
    assert_eq!(walked, 3, "add, show and update");
}

#[tokio::test]
async fn a_valid_token_on_an_unknown_route_gets_404_and_the_unix_socket_stays_open() {
    let s = setup().await;
    let admin_token = s.issuer.token("adam", &["admins"]);
    let (status, ..) = call(&s.token_socket, "GET", "/v1/nope", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // No token anywhere on the break-glass socket, and it keeps full access.
    let (status, body) = admin(&s.h, "GET", "/v1/apps", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post_app(&s.h, "y", spec("y.example.com")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn doctor_reports_the_listener_and_the_providers_keys() {
    let s = setup().await;
    let (status, report) = admin(&s.h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK);
    let checks: Vec<&Value> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"] == "admin.http")
        .collect();
    // `panel` is a configured client that is not in apps.toml yet: a warning, and the keys are fine.
    let says = |status: &str, needle: &str| {
        checks.iter().any(|c| {
            c["status"] == status && c["message"].as_str().unwrap_or_default().contains(needle)
        })
    };
    assert!(says("warn", "panel"), "{checks:?}");
    assert!(says("ok", "signing keys"), "{checks:?}");
}

/// Every endpoint the router registers is declared in `ENDPOINTS` (and so has a scope), and the other
/// way round. The router cannot be enumerated at runtime, so this reads the sources: a route is added
/// with `endpoints::<NAME>.path` (the rule of `endpoints.rs`), a declaration is an entry of `ENDPOINTS`.
/// An undeclared route would be refused by the token listener (fail closed) — this catches it in CI
/// instead of as a mysterious 403.
#[test]
fn every_routed_endpoint_is_declared_and_every_declared_one_is_routed() {
    use std::collections::BTreeSet;
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let idents = |text: &str, prefix: &str| -> BTreeSet<String> {
        text.match_indices(prefix)
            .map(|(i, _)| {
                text[i + prefix.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty() && name != "ENDPOINTS")
            .collect()
    };

    let mut routed = BTreeSet::new();
    for entry in std::fs::read_dir(crates.join("weglarka-daemon/src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            // Only files that register routes; `endpoints::X` elsewhere (docs, probes) is not a route.
            if text.contains(".route(") || text.contains("routing::") {
                routed.extend(
                    idents(&text, "endpoints::")
                        .into_iter()
                        .filter(|n| text.contains(&format!("endpoints::{n}.path"))),
                );
            }
        }
    }

    let endpoints_rs =
        std::fs::read_to_string(crates.join("weglarka-api/src/endpoints.rs")).unwrap();
    let array = &endpoints_rs[endpoints_rs.find("pub const ENDPOINTS").unwrap()..];
    let array = &array[..array.find("];").unwrap()];
    let declared: BTreeSet<String> = array
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_suffix(','))
        .filter(|l| {
            l.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_owned)
        .collect();

    assert_eq!(
        declared.len(),
        ENDPOINTS.len(),
        "the scan must see every entry of ENDPOINTS"
    );
    // A route chains several methods on one path (`get(..).post(..)`) and names the constant only once,
    // so compare by path. An extra *method* on a known path is still caught: the token listener has no
    // declaration for it and refuses it (and `every_declared_endpoint_...` covers the declared ones).
    let path_of = |name: &String| -> String {
        let at = endpoints_rs
            .find(&format!("pub const {name}: Endpoint"))
            .unwrap_or_else(|| panic!("{name} is not a constant of endpoints.rs"));
        let rest = &endpoints_rs[at..];
        let from = rest.find("path: \"").unwrap() + "path: \"".len();
        rest[from..from + rest[from..].find('"').unwrap()].to_owned()
    };
    let routed_paths: BTreeSet<String> = routed.iter().map(path_of).collect();
    let declared_paths: BTreeSet<String> = declared.iter().map(path_of).collect();
    assert!(
        routed.is_subset(&declared),
        "routed but undeclared: {:?}",
        routed.difference(&declared).collect::<Vec<_>>()
    );
    assert_eq!(
        routed_paths,
        declared_paths,
        "declared but unrouted paths: {:?}",
        declared_paths.difference(&routed_paths).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn without_admin_http_there_is_no_token_listener() {
    let h = harness().await;
    assert!(h.running.admin_token_socket.is_none());
    assert!(!h.root.join("state/run/admin-token").exists());
}

#[test]
fn audience_constant_matches_the_configured_audience() {
    // The fixtures above rely on the test issuer's audience being the one in `SECTIONS`.
    assert!(SECTIONS.contains(&format!("audience = \"{AUDIENCE}\"")));
}
