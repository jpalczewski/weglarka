//! The read-mostly pages and their live streams, against a fake daemon that answers by path and
//! by bearer token (`tok-read` / `tok-admin`), the way the real token listener does.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use weglarka_api::{AccessEntry, AccessFrame, LogFrame, ShowAppResponse};
use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_ISSUER, ENV_PUBLIC_URL, ENV_SOCKET,
    ENV_TIMEOUT_SECS,
};
use weglarka_panel::headers::CONTENT_SECURITY_POLICY_VALUE;
use weglarka_panel::session::{Session, Tokens, User};
use weglarka_panel::{AppState, PanelConfig, Secret, router};
use weglarka_unix_http::testing::{Mock, Reply, Seen, mock_seen};

const SESSION: &str = "__Host-weglarka-session";
/// A value that must never be rendered anywhere.
const ENV_SECRET: &str = "S3CRET-ENV-VALUE-91c2";

/// Every protected GET page.
const PAGES: &[&str] = &[
    "/",
    "/apps",
    "/apps/web",
    "/doctor",
    "/volumes",
    "/networks",
    "/sites",
    "/notifications",
    "/certificates",
    "/events",
    "/config",
];

fn json_reply(value: Value) -> Reply {
    Reply::new(200, value.to_string())
}

fn error(status: u16, code: &str, message: &str) -> Reply {
    Reply::new(
        status,
        json!({"code": code, "message": message}).to_string(),
    )
}

fn bearer(seen: &Seen) -> &str {
    seen.header("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

fn app_json(token: &str) -> Value {
    let admin = token == "tok-admin";
    let mut v = json!({
        "name": "web",
        "spec": {
            "image": "ghcr.io/example/web:1",
            "domains": ["web.example.com"],
            "port": 8080,
            "env": { "API_KEY": if admin { ENV_SECRET } else { "" }, "MODE": if admin { "prod" } else { "" } },
            "secrets": [{ "secret": "db", "kind": "env", "var": "DB_URL" }],
            "volumes": [{ "name": "data", "target": "/data" }],
        },
        "state": {
            "generation": 3,
            "current": format!("sha256:{}", "a".repeat(64)),
        },
        "runtime": "running",
        "restarts": 2,
        "health": "healthy",
        "started_at": "2026-10-29T10:00:00Z",
        "configs": [{ "source": "web/app.conf", "target": "/etc/app.conf", "status": "ok" }],
    });
    if !admin {
        v["redacted"] = json!(true);
    }
    v
}

/// What the fake daemon says; tests change fields before they start it.
#[derive(Clone)]
struct Script {
    /// Replaces the answer for a path (status, code, message).
    fail: Vec<(&'static str, u16, &'static str)>,
    events: Vec<Value>,
    boot: &'static str,
    /// Frames for the logs stream, per connection number (0-based); the last repeats, held open.
    logs: Vec<(Vec<LogFrame>, bool)>,
    /// The same for the access stream.
    access: Vec<(Vec<AccessFrame>, bool)>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            fail: Vec::new(),
            events: vec![event(1, "deploy_succeeded"), event(2, "deploy_failed")],
            boot: "b00f-1",
            logs: vec![(vec![LogFrame::Stdout(b"hello\n".to_vec())], true)],
            access: vec![(
                vec![AccessFrame::Entry(entry("/index.html", "curl/8"))],
                true,
            )],
        }
    }
}

fn event(seq: u64, kind: &str) -> Value {
    json!({
        "seq": seq, "ts": "2026-10-29T12:00:00Z", "severity": if kind.contains("failed") { "warning" } else { "info" },
        "kind": kind, "app": "web", "message": format!("{kind} for <web>"),
    })
}

fn entry(path: &str, agent: &str) -> AccessEntry {
    AccessEntry {
        time: "2026-10-31T12:00:00Z".into(),
        host: "web.example.com".into(),
        remote_addr: "203.0.113.7".into(),
        method: "GET".into(),
        path: path.into(),
        status: 200,
        bytes_sent: 512,
        request_time: 0.0125,
        user_agent: agent.into(),
        ..AccessEntry::default()
    }
}

fn frames(frames: &[LogFrame]) -> Vec<weglarka_unix_http::Bytes> {
    frames.iter().map(|f| f.encode().into()).collect()
}

async fn fake_daemon(script: Script) -> Mock {
    let logs_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let access_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    mock_seen(move |seen| {
        let token = bearer(seen);
        if token != "tok-read" && token != "tok-admin" {
            return error(401, "unauthorized", "bad token");
        }
        if let Some((_, status, code)) = script.fail.iter().find(|(p, ..)| *p == seen.path) {
            return match *status {
                500..=599 if *code == "html" => Reply::new(*status, "<html>internal secret trace</html>"),
                _ => error(*status, code, "from the daemon"),
            };
        }
        match seen.path.as_str() {
            "/v1/status" => json_reply(json!({
                "api_version": "1", "daemon_version": "0.9.1", "podman_version": "6.1.0",
                "apps": [{ "name": "web", "image": "ghcr.io/example/web:1", "domains": ["web.example.com"], "runtime": "running" },
                         { "name": "db", "image": "ghcr.io/example/db:1", "domains": [], "runtime": "unhealthy" }],
            })),
            "/v1/apps" => json_reply(json!({"apps": [
                { "name": "web", "image": "ghcr.io/example/web:1", "domains": ["web.example.com"], "runtime": "running",
                  "digest": format!("sha256:{}", "a".repeat(64)) }]})),
            "/v1/apps/web" => json_reply(app_json(token)),
            "/v1/apps/web/volumes" => json_reply(json!({"volumes": [
                { "name": "data", "target": "/data", "podman_name": "web.data", "exists": true }]})),
            "/v1/volumes" => json_reply(json!({"volumes": [
                { "name": "media", "podman_name": "wg-shared-media", "members": ["web"], "exists": true,
                  "uid_range": { "start": 100000, "size": 65536 } }]})),
            "/v1/networks" => json_reply(json!({"networks": [
                { "name": "backend", "podman_name": "net-shared-backend", "members": ["web", "db"], "exists": false }]})),
            "/v1/sites" => json_reply(json!({"sites": [{ "name": "blog", "image": "ghcr.io/example/blog", "envs": [
                { "env": "prod", "instance": "blog-prod", "track": "stable", "promote_from": null,
                  "domains": ["blog.example.com"], "current": null, "previous": null }]}]})),
            "/v1/notifications" => json_reply(json!({
                "enabled": true, "channels": [{ "name": "ntfy", "min_severity": "warning", "pending": 1 }],
                "pending": 1, "dropped": 0, "last_error": "timeout talking to ntfy" })),
            "/v1/certificates" => json_reply(json!({
                "acme_enabled": true, "renew_before_days": 30, "failures": 1, "certificates": [
                  { "id": "web", "names": ["web.example.com"], "wildcard": false, "status": "renewal_due",
                    "not_after": "2026-11-10T00:00:00Z", "days_left": 12, "failed": true },
                  { "id": "star", "names": ["*.example.org"], "wildcard": true, "status": "missing", "failed": false },
                  { "id": "sub", "names": ["a.example.org"], "wildcard": false, "status": "covered", "covered_by": "star", "failed": false }]})),
            "/v1/doctor" => json_reply(json!({"checks": [
                { "id": "runtime.podman", "status": "ok", "message": "podman 6.1" },
                { "id": "acme.dns", "status": "warn", "message": "no DNS provider", "hint": "set [acme.dns]" },
                { "id": "state.orphan", "status": "fail", "message": "orphan <b>secret</b>" }]})),
            "/v1/events" => {
                let since: u64 = seen
                    .query
                    .as_deref()
                    .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("since=")))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let events: Vec<&Value> = script
                    .events
                    .iter()
                    .filter(|e| e["seq"].as_u64().unwrap() > since)
                    .collect();
                json_reply(json!({
                    "events": events, "boot_id": script.boot,
                    "next_seq": script.events.iter().map(|e| e["seq"].as_u64().unwrap()).max().unwrap_or(0),
                }))
            }
            "/v1/config" => json_reply(json!({
                "runtime": { "reconcile_interval_secs": 30, "allow_privileged_host_ports": false, "host_mounts": [], "group_add": [] },
                "ingress": { "mode": "behind", "bind": "127.0.0.1:8080", "nginx_image": "docker.io/library/nginx:1", "custom_trusted_proxies": false },
                "admin": {}, "webhook": { "domain": "hooks.example.com" },
                "platform": { "kind": "systemd", "memory": "256m", "pids_limit": 256 },
                "host_configs": false,
                "monitor": { "crash_loop_restarts": 3, "crash_loop_window_secs": 300, "unhealthy_observations": 3 },
            })),
            "/v1/apps/web/logs" => {
                if token != "tok-admin" {
                    return error(403, "forbidden", "admin only");
                }
                let tail0 = seen.query.as_deref().is_some_and(|q| q.contains("tail=0"));
                if tail0 {
                    return Reply::new(200, "");
                }
                let n = logs_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (list, hold) = &script.logs[n.min(script.logs.len() - 1)];
                let reply = Reply::chunks(200, frames(list));
                if *hold { reply.hold_open() } else { reply }
            }
            "/v1/apps/web/access" => {
                if token != "tok-admin" {
                    return error(403, "forbidden", "admin only");
                }
                let n = access_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (list, hold) = &script.access[n.min(script.access.len() - 1)];
                let chunks: Vec<weglarka_unix_http::Bytes> = list.iter().map(|f| f.encode().into()).collect();
                let reply = Reply::chunks(200, chunks);
                if *hold { reply.hold_open() } else { reply }
            }
            _ => error(404, "not_found", "no such route"),
        }
    })
    .await
}

struct Site {
    app: Router,
    state: AppState,
    daemon: Mock,
}

async fn site(script: Script) -> Site {
    site_with(fake_daemon(script).await, &[]).await
}

async fn site_with(daemon: Mock, extra: &[(&str, &str)]) -> Site {
    let socket = daemon.socket.display().to_string();
    let extra: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let config = PanelConfig::from_lookup(|var| {
        if let Some((_, v)) = extra.iter().find(|(k, _)| k == var) {
            return Some(v.clone());
        }
        match var {
            ENV_CLIENT_ID => Some("panel".into()),
            ENV_CLIENT_SECRET => Some("secret".into()),
            ENV_ISSUER => Some("https://auth.example.com".into()),
            ENV_PUBLIC_URL => Some("https://panel.example.com".into()),
            ENV_API_AUDIENCE => Some("https://admin.example.com/api/".into()),
            ENV_SOCKET => Some(socket.clone()),
            _ => None,
        }
    })
    .unwrap();
    let mut state = AppState::new(config).unwrap();
    state.stream_poll = Duration::from_millis(40);
    Site {
        app: router(state.clone()),
        state,
        daemon,
    }
}

struct Login {
    cookie: String,
    csrf: String,
    session: Arc<Session>,
}

/// A signed-in browser: a session holding `token`, created directly in the store.
fn login(site: &Site, token: &str) -> Login {
    let session = Session::new(
        User {
            sub: "u1".into(),
            name: "Ada <Admin>".into(),
        },
        Tokens {
            access: Arc::new(Secret::new(token)),
            refresh: None,
            access_expires: site.state.clock.now() + Duration::from_secs(3600),
            refresh_retry_at: None,
        },
        site.state.clock.now(),
    );
    let csrf = session.csrf.clone();
    let id = site.state.sessions.insert(session).unwrap();
    let session = site.state.sessions.peek(&id).unwrap();
    Login {
        cookie: format!("{SESSION}={id}"),
        csrf,
        session,
    }
}

async fn get(
    site: &Site,
    who: Option<&Login>,
    path: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(who) = who {
        builder = builder.header(header::COOKIE, &who.cookie);
    }
    let response = site
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// The structural promises every page makes.
fn assert_page_is_clean(path: &str, headers: &axum::http::HeaderMap, html: &str) {
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        CONTENT_SECURITY_POLICY_VALUE,
        "{path}"
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
    let lower = html.to_ascii_lowercase();
    for banned in [
        "<style",
        " style=",
        "javascript:",
        "hx-on",
        "<iframe",
        "<object",
        "<embed",
        "|safe",
    ] {
        assert!(!lower.contains(banned), "{path} contains {banned}");
    }
    for tag in lower.split("<script").skip(1) {
        let open = tag.split('>').next().unwrap();
        assert!(
            open.contains(" src=\"/static/"),
            "{path} has an inline or foreign <script>"
        );
    }
    // No inline event handler attributes (`onclick=`, ...).
    for (i, _) in lower.match_indices(" on") {
        let name: String = lower[i + 3..]
            .chars()
            .take_while(char::is_ascii_lowercase)
            .collect();
        assert!(
            !(name.len() > 2 && lower[i + 3 + name.len()..].starts_with('=')),
            "{path} has an inline handler on{name}"
        );
    }
    // Every URL the page loads or links to is on this origin.
    for attr in [
        "href=\"",
        "src=\"",
        "action=\"",
        "sse-connect=\"",
        "hx-get=\"",
        "hx-post=\"",
    ] {
        for (i, _) in html.match_indices(attr) {
            let value = &html[i + attr.len()..];
            let value = &value[..value.find('"').unwrap()];
            assert!(
                value.starts_with('/') || value.starts_with('#'),
                "{path}: {attr}{value}\" is not same-origin"
            );
        }
    }
    assert!(
        // TODO: this also rejects a legitimate `https://` shown as text; narrow it to attribute
        // values if such a page appears.
        !html.contains("http://") && !html.contains("https://"),
        "{path} names an external URL"
    );
    assert!(!html.contains(ENV_SECRET), "{path} leaks an env value");
    assert!(
        !html.contains("tok-read") && !html.contains("tok-admin"),
        "{path} leaks a token"
    );
}

#[tokio::test]
async fn every_page_renders_for_a_read_principal() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-read");
    let expect = [
        ("/", "Recent events"),
        ("/apps", "ghcr.io/example/web:1"),
        ("/apps/web", "Redacted view"),
        ("/doctor", "orphan &#60;b&#62;secret"),
        ("/volumes", "wg-shared-media"),
        ("/networks", "net-shared-backend"),
        ("/sites", "blog-prod"),
        ("/notifications", "timeout talking to ntfy"),
        ("/certificates", "missing key or certificate"),
        ("/events", "deploy_failed"),
        ("/config", "hooks.example.com"),
    ];
    assert_eq!(expect.len(), PAGES.len());
    for (path, needle) in expect {
        let (status, headers, html) = get(&site, Some(&who), path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            html.contains(needle)
                || html.contains(&needle.replace("deploy_failed", "deploy failed")),
            "{path} lacks {needle:?}\n{html}"
        );
        assert_page_is_clean(path, &headers, &html);
        // The user's own token went to the daemon, nobody else's.
        assert!(
            site.daemon
                .seen
                .lock()
                .unwrap()
                .iter()
                .all(|s| bearer(s) == "tok-read")
        );
        // The logout form carries the CSRF token and the user name is escaped.
        assert!(html.contains(&format!("value=\"{}\"", who.csrf)), "{path}");
        assert!(html.contains("Ada &#60;Admin&#62;"), "{path}");
    }
}

#[tokio::test]
async fn pages_show_status_as_words_and_group_doctor_checks() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-read");
    let (_, _, doctor) = get(&site, Some(&who), "/doctor").await;
    let failing = doctor.find("Failing").unwrap();
    let warning = doctor.find("Warning").unwrap();
    let ok = doctor.find(">OK<").unwrap();
    assert!(failing < warning && warning < ok, "worst group first");
    assert!(doctor.contains("Hint: set [acme.dns]"));
    let (_, _, certs) = get(&site, Some(&who), "/certificates").await;
    assert!(
        certs.contains("covered by star")
            && certs.contains("renewal due")
            && certs.contains("last renewal failed")
    );
    let (_, _, dash) = get(&site, Some(&who), "/").await;
    assert!(dash.contains("1 running, 1 needing attention"), "{dash}");
    assert!(dash.contains("12 days left"));
}

#[tokio::test]
async fn a_redacted_view_is_badged_and_env_values_never_appear() {
    let site = site(Script::default()).await;
    // The fixture really is a `ShowAppResponse` of both shapes.
    assert!(serde_json::from_value::<ShowAppResponse>(app_json("tok-admin")).is_ok());
    for (token, redacted) in [("tok-read", true), ("tok-admin", false)] {
        let who = login(&site, token);
        let (status, headers, html) = get(&site, Some(&who), "/apps/web").await;
        assert_eq!(status, StatusCode::OK);
        assert_page_is_clean("/apps/web", &headers, &html);
        assert_eq!(html.contains("Redacted view"), redacted, "{token}");
        // Names only, whoever asks.
        assert!(html.contains("API_KEY") && html.contains("MODE"));
        assert!(!html.contains("prod</"), "{token}");
        // Never an edit or copy action.
        let lower = html.to_ascii_lowercase();
        assert!(
            !lower.contains("edit") && !lower.contains("copy") && !lower.contains("<textarea"),
            "{token}"
        );
        assert!(html.contains("DB_URL") && html.contains("ghcr.io/example/web:1"));
    }
}

#[tokio::test]
async fn the_logs_section_is_offered_only_when_the_daemon_allows_it() {
    let site = site(Script::default()).await;
    let read = login(&site, "tok-read");
    let admin = login(&site, "tok-admin");
    let (_, _, html) = get(&site, Some(&read), "/apps/web").await;
    assert!(!html.contains("logs/stream") && !html.contains(">Logs<"));
    let (status, _, html) = get(&site, Some(&read), "/apps/web/logs/stream").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("not allowed"), "{html}");

    let (_, headers, html) = get(&site, Some(&admin), "/apps/web").await;
    // The page only offers the section; the stream element comes with the Start button's fragment.
    assert!(html.contains("hx-get=\"/apps/web/logs\"") && !html.contains("sse-connect"));
    assert_page_is_clean("/apps/web", &headers, &html);
    let (status, headers, html) = get(&site, Some(&admin), "/apps/web/logs").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("sse-connect=\"/apps/web/logs/stream\""),
        "{html}"
    );
    assert_page_is_clean("/apps/web/logs", &headers, &html);
    let (status, ..) = get(&site, Some(&read), "/apps/web/logs").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_requests_are_refused_without_a_daemon_call() {
    let site = site(Script::default()).await;
    for path in PAGES.iter().chain(&[
        "/events/stream",
        "/apps/web/logs",
        "/apps/web/logs/stream",
        "/apps/web/access",
        "/apps/web/access/stream",
        "/nope",
    ]) {
        let (status, headers, _) = get(&site, None, path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY_VALUE
        );
    }
    assert!(site.daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn daemon_failures_map_to_pages_and_never_leak_bodies() {
    // 403 on a `read` call: the identity has no access at all, so the session ends.
    let site1 = site(Script {
        fail: vec![("/v1/doctor", 403, "forbidden")],
        ..Script::default()
    })
    .await;
    let who = login(&site1, "tok-read");
    let (status, headers, html) = get(&site1, Some(&who), "/doctor").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(html.contains("Sign in"));
    assert!(
        headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert!(who.session.is_ended() && site1.state.sessions.is_empty());

    // 403 on an `admin` call: a polite page that keeps the navigation and the session.
    let site1 = site(Script::default()).await;
    let who = login(&site1, "tok-read");
    let (status, headers, html) = get(&site1, Some(&who), "/apps/web/logs/stream").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        html.contains("No access") && html.contains("href=\"/apps\""),
        "{html}"
    );
    assert_page_is_clean("/apps/web/logs/stream", &headers, &html);
    assert!(!who.session.is_ended() && !site1.state.sessions.is_empty());
    assert_eq!(get(&site1, Some(&who), "/apps").await.0, StatusCode::OK);

    // 500 with a body that is not the envelope: retryable page, body not quoted.
    let site2 = site(Script {
        fail: vec![("/v1/doctor", 500, "html")],
        ..Script::default()
    })
    .await;
    let who = login(&site2, "tok-read");
    let (status, _, html) = get(&site2, Some(&who), "/doctor").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(html.contains("Try again") && html.contains("href=\"/doctor\""));
    assert!(!html.contains("internal secret trace"));

    // 404 shows the API's own message, escaped.
    let (status, _, html) = get(&site2, Some(&who), "/apps/ghost").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(html.contains("no such route"));
    let (status, _, _) = get(&site2, Some(&who), "/apps/a%2Fb").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 401 from the daemon ends the session.
    let site3 = site(Script::default()).await;
    let who = login(&site3, "tok-revoked");
    let (status, headers, html) = get(&site3, Some(&who), "/doctor").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(html.contains("Sign in"));
    assert!(
        headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert!(who.session.is_ended());
    assert!(site3.state.sessions.is_empty());
    let (status, ..) = get(&site3, Some(&who), "/doctor").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unreachable_or_slow_daemon_gives_a_retryable_page() {
    let mut s = site(Script::default()).await;
    s.state.config = Arc::new(
        PanelConfig::from_lookup(|v| match v {
            ENV_CLIENT_ID => Some("panel".into()),
            ENV_CLIENT_SECRET => Some("secret".into()),
            ENV_ISSUER => Some("https://auth.example.com".into()),
            ENV_PUBLIC_URL => Some("https://panel.example.com".into()),
            ENV_API_AUDIENCE => Some("https://admin.example.com/api/".into()),
            ENV_SOCKET => Some("/nonexistent/wgl.sock".into()),
            _ => None,
        })
        .unwrap(),
    );
    s.state.daemon = weglarka_panel::DaemonClient::from_config(&s.state.config);
    s.app = router(s.state.clone());
    let who = login(&s, "tok-read");
    let (status, _, html) = get(&s, Some(&who), "/apps").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(html.contains("unreachable") && html.contains("Try again"));

    let slow = mock_seen(|_| Reply::new(200, "{}").head_delay(Duration::from_secs(4))).await;
    let s = site_with(slow, &[(ENV_TIMEOUT_SECS, "1")]).await;
    let who = login(&s, "tok-read");
    let (status, _, html) = get(&s, Some(&who), "/apps").await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert!(html.contains("Try again"));
}

#[tokio::test]
async fn vendored_assets_are_served_cacheable_and_nosniff() {
    let site = site(Script::default()).await;
    for (name, immutable) in [
        ("htmx-2.0.11.min.js", true),
        ("htmx-ext-sse-2.2.4.min.js", true),
        ("alpine-csp-3.17.4.min.js", true),
        ("app.js", false),
        ("app.css", false),
    ] {
        let (status, headers, body) = get(&site, None, &format!("/static/{name}")).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(!body.is_empty());
        let cache = headers[header::CACHE_CONTROL].to_str().unwrap();
        assert_eq!(cache.contains("immutable"), immutable, "{name}: {cache}");
    }
    // Every file has a validator, and a matching one gets a 304 with the same cache policy.
    let etag = {
        let r = site
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/static/app.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        r.headers()[header::ETAG].to_str().unwrap().to_owned()
    };
    let r = site
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/app.css")
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(r.headers()[header::CACHE_CONTROL], "public, no-cache");
    // The page configures htmx as ADR 0057 wants and loads only these files.
    let who = login(&site, "tok-read");
    let (_, _, html) = get(&site, Some(&who), "/").await;
    assert!(html.contains("&quot;allowEval&quot;") || html.contains("\"allowEval\": false"));
    assert!(html.contains("\"includeIndicatorStyles\": false"));
    assert_eq!(html.matches("<script").count(), 4);
}

// ---- SSE ------------------------------------------------------------------------------------

/// Reads an SSE body until `needle` shows up (or `within` passes), returning everything read.
async fn read_until(body: &mut Body, needle: &str, within: Duration) -> Result<String, String> {
    let deadline = Instant::now() + within;
    let mut text = String::new();
    while !text.contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    text.push_str(&String::from_utf8_lossy(data));
                }
            }
            Ok(Some(Err(e))) => return Err(format!("body error {e}; read so far: {text}")),
            Ok(None) => return Err(format!("stream ended; read so far: {text}")),
            Err(_) => return Err(format!("timed out; read so far: {text}")),
        }
    }
    Ok(text)
}

async fn open_stream(
    site: &Site,
    who: &Login,
    path: &str,
    last_event_id: Option<&str>,
) -> axum::response::Response {
    let mut b = Request::builder()
        .uri(path)
        .header(header::COOKIE, &who.cookie);
    if let Some(id) = last_event_id {
        b = b.header("last-event-id", id);
    }
    site.app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

const WAIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn events_stream_pushes_rows_and_resumes_by_seq() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-read");
    // The page hands the stream its cursor.
    let (_, _, page) = get(&site, Some(&who), "/events").await;
    assert!(
        page.contains("sse-connect=\"/events/stream?since=2&#38;boot=b00f-1\""),
        "{page}"
    );

    // A fresh stream from the start sends both rows, escaped, each with `boot:seq` ids.
    let response = open_stream(&site, &who, "/events/stream?since=0&boot=b00f-1", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(
        response.headers()[header::CONTENT_SECURITY_POLICY],
        CONTENT_SECURITY_POLICY_VALUE
    );
    let mut body = response.into_body();
    let text = read_until(&mut body, "id: b00f-1:2", WAIT).await.unwrap();
    assert!(text.contains("id: b00f-1:1") && text.contains("deploy failed"));
    assert!(
        text.contains("for &#60;web&#62;") && !text.contains("<web>"),
        "{text}"
    );
    drop(body);

    // Reconnecting with Last-Event-ID continues after that seq: the daemon is asked `since=2`.
    let before = site.daemon.seen.lock().unwrap().len();
    let response = open_stream(
        &site,
        &who,
        "/events/stream?since=0&boot=b00f-1",
        Some("b00f-1:2"),
    )
    .await;
    let mut body = response.into_body();
    let _ = read_until(&mut body, "never", Duration::from_millis(300)).await;
    drop(body);
    let seen = site.daemon.seen.lock().unwrap();
    let polls: Vec<_> = seen[before..]
        .iter()
        .filter(|s| s.path == "/v1/events")
        .collect();
    assert!(!polls.is_empty());
    assert!(
        polls
            .iter()
            .all(|s| s.query.as_deref() == Some("since=2&boot=b00f-1")),
        "{polls:?}"
    );
}

#[tokio::test]
async fn events_stream_ends_with_the_session_and_when_the_browser_leaves() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-read");
    let response = open_stream(&site, &who, "/events/stream?since=2&boot=b00f-1", None).await;
    let mut body = response.into_body();
    assert_eq!(site.state.streams.open_streams(), 1);
    // Logout ends the session, and with it the stream.
    let logout = Request::builder()
        .method(Method::POST)
        .uri("/auth/logout")
        .header(header::COOKIE, &who.cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("_csrf={}", who.csrf)))
        .unwrap();
    assert!(
        site.app
            .clone()
            .oneshot(logout)
            .await
            .unwrap()
            .status()
            .is_redirection()
    );
    let err = read_until(&mut body, "never", WAIT).await.unwrap_err();
    assert!(err.starts_with("stream ended"), "{err}");
    drop(body);
    assert_eq!(site.state.streams.open_streams(), 0);

    // A browser that goes away frees its slot.
    let who = login(&site, "tok-read");
    let response = open_stream(&site, &who, "/events/stream", None).await;
    assert_eq!(site.state.streams.open_streams(), 1);
    drop(response);
    assert_eq!(site.state.streams.open_streams(), 0);
}

#[tokio::test]
async fn streams_per_session_are_limited() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-read");
    let mut held = Vec::new();
    for _ in 0..weglarka_panel::live::MAX_STREAMS_PER_SESSION {
        let r = open_stream(&site, &who, "/events/stream", None).await;
        assert_eq!(r.status(), StatusCode::OK);
        held.push(r);
    }
    let r = open_stream(&site, &who, "/events/stream", None).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another session is not affected.
    let other = login(&site, "tok-read");
    assert_eq!(
        open_stream(&site, &other, "/events/stream", None)
            .await
            .status(),
        StatusCode::OK
    );
    drop(held);
}

async fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn log_lines_are_escaped_stripped_and_capped() {
    let long = format!("{}\n", "x".repeat(5000));
    let site = site(Script {
        logs: vec![(
            vec![
                LogFrame::Stdout(b"<script>alert(1)</script> & \x1b[31mred\x1b[0m\n".to_vec()),
                LogFrame::Stderr(b"oops \"quoted\"\r\n".to_vec()),
                LogFrame::Stdout(long.into_bytes()),
                LogFrame::Stdout(b"par".to_vec()),
                LogFrame::Stdout(b"tial\n".to_vec()),
            ],
            true,
        )],
        ..Script::default()
    })
    .await;
    let who = login(&site, "tok-admin");
    let response = open_stream(&site, &who, "/apps/web/logs/stream", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let text = read_until(&mut body, "partial", WAIT).await.unwrap();
    assert!(
        !text.contains("<script>") && text.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}') && text.contains("[31mred"));
    assert!(
        text.contains("oops &#34;quoted&#34;") || text.contains("oops &quot;quoted&quot;"),
        "{text}"
    );
    assert!(text.contains("event: lines"));
    assert!(!text.contains(&"x".repeat(2100)) && text.contains('…'));
    // The upstream request carried the user's token, asked to follow, and started from a tail.
    let seen = site.daemon.seen.lock().unwrap();
    let open = seen
        .iter()
        .find(|s| s.path == "/v1/apps/web/logs" && s.query.as_deref() != Some("tail=0"))
        .unwrap();
    assert_eq!(bearer(open), "tok-admin");
    assert!(open.query.as_deref().unwrap().contains("follow=true"));
}

#[tokio::test]
async fn token_expiry_reconnects_with_since_and_dropping_the_page_closes_upstream() {
    let site = site(Script {
        logs: vec![
            (
                vec![LogFrame::Stdout(b"one\n".to_vec()), LogFrame::TokenExpired],
                false,
            ),
            (vec![LogFrame::Stdout(b"two\n".to_vec())], true),
        ],
        ..Script::default()
    })
    .await;
    let who = login(&site, "tok-admin");
    let response = open_stream(&site, &who, "/apps/web/logs/stream", None).await;
    let mut body = response.into_body();
    let text = read_until(&mut body, "two", WAIT).await.unwrap();
    assert!(text.contains("one"));
    {
        let seen = site.daemon.seen.lock().unwrap();
        let opens: Vec<_> = seen
            .iter()
            .filter(|s| s.path == "/v1/apps/web/logs" && s.query.as_deref() != Some("tail=0"))
            .collect();
        assert_eq!(opens.len(), 2);
        let q = opens[1].query.as_deref().unwrap();
        assert!(
            q.contains("follow=true") && q.contains("since=") && !q.contains("tail="),
            "{q}"
        );
        assert!(opens[0].query.as_deref().unwrap().contains("tail=200"));
    }
    // The browser disconnects: the daemon connection goes with it.
    wait_for("the held upstream", || {
        site.daemon.held.load(std::sync::atomic::Ordering::SeqCst) == 1
    })
    .await;
    drop(body);
    wait_for("the upstream to be dropped", || {
        site.daemon.held.load(std::sync::atomic::Ordering::SeqCst) == 0
    })
    .await;
}

#[tokio::test]
async fn logout_closes_the_logs_stream_and_its_upstream() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-admin");
    let response = open_stream(&site, &who, "/apps/web/logs/stream", None).await;
    let mut body = response.into_body();
    read_until(&mut body, "hello", WAIT).await.unwrap();
    wait_for("the held upstream", || {
        site.daemon.held.load(std::sync::atomic::Ordering::SeqCst) == 1
    })
    .await;
    who.session.end();
    let err = read_until(&mut body, "never", WAIT).await.unwrap_err();
    assert!(err.starts_with("stream ended"), "{err}");
    drop(body);
    wait_for("the upstream to be dropped", || {
        site.daemon.held.load(std::sync::atomic::Ordering::SeqCst) == 0
    })
    .await;
    assert_eq!(site.state.streams.open_streams(), 0);
}

#[tokio::test]
async fn a_daemon_log_error_and_end_are_reported_in_text() {
    let site = site(Script {
        logs: vec![(vec![LogFrame::Error("podman <went> away".into())], false)],
        ..Script::default()
    })
    .await;
    let who = login(&site, "tok-admin");
    let mut body = open_stream(&site, &who, "/apps/web/logs/stream", None)
        .await
        .into_body();
    let text = read_until(&mut body, "away", WAIT).await.unwrap();
    assert!(text.contains("event: status"), "{text}");
    // A terminal status is followed by `done`, which the page's `sse-close` turns into a closed
    // EventSource (no reconnect, so no duplicated tail).
    let more = read_until(&mut body, "event: done", WAIT)
        .await
        .map(|t| text.clone() + &t)
        .unwrap();
    assert!(more.contains("event: done"));
    assert!(
        text.contains("podman &#60;went&#62; away") || text.contains("podman &lt;went&gt; away"),
        "{text}"
    );
    assert!(
        read_until(&mut body, "never", WAIT)
            .await
            .unwrap_err()
            .starts_with("stream ended")
    );
}

/// Not a test: serves the panel on `127.0.0.1:$PANEL_DEMO_PORT` over the fake daemon, with a session
/// for `tok-admin`, so a real browser can be pointed at it. `cargo test -p weglarka-panel --test it
/// serve_for_a_browser -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "manual: serves the panel for a browser"]
async fn serve_for_a_browser() {
    let port = std::env::var("PANEL_DEMO_PORT").unwrap_or_else(|_| "8099".into());
    let token = std::env::var("PANEL_DEMO_TOKEN").unwrap_or_else(|_| "tok-admin".into());
    let site = site(Script::default()).await;
    let who = login(&site, &token);
    println!("COOKIE {}", who.cookie);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let app = site.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_secs(1800)).await;
}

#[tokio::test]
async fn the_app_page_decides_on_logs_from_redacted_and_never_probes() {
    let site = site(Script::default()).await;
    for token in ["tok-read", "tok-admin"] {
        let who = login(&site, token);
        get(&site, Some(&who), "/apps/web").await;
    }
    assert!(
        site.daemon
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|s| s.path != "/v1/apps/web/logs")
    );
}

#[tokio::test]
async fn a_malformed_app_name_is_a_404_without_a_daemon_call() {
    let site = site(Script::default()).await;
    let who = login(&site, "tok-admin");
    for path in [
        "/apps/a%2Fb",
        "/apps/..",
        "/apps/UPPER_x!",
        "/apps/a%2Fb/logs/stream",
    ] {
        let (status, ..) = get(&site, Some(&who), path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(site.daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_events_stream_answers_a_refusal_with_a_status_not_a_reconnect_loop() {
    let site = site(Script {
        fail: vec![("/v1/events", 403, "forbidden")],
        ..Script::default()
    })
    .await;
    let who = login(&site, "tok-read");
    let r = open_stream(&site, &who, "/events/stream?since=0", None).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(
        who.session.is_ended(),
        "events need only read: no access at all"
    );
    assert_eq!(site.state.streams.open_streams(), 0);

    // A token the daemon no longer accepts ends the session.
    let site = site_with(fake_daemon(Script::default()).await, &[]).await;
    let who = login(&site, "tok-revoked");
    let r = open_stream(&site, &who, "/events/stream?since=0", None).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(who.session.is_ended());
}

// ---- access log -----------------------------------------------------------------------------

/// The requests the daemon saw for the access stream, in order.
fn access_opens(site: &Site) -> Vec<weglarka_unix_http::testing::Seen> {
    site.daemon
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == "/v1/apps/web/access")
        .cloned()
        .collect()
}

#[tokio::test]
async fn the_access_section_is_admin_only_and_opens_nothing_on_page_load() {
    let site = site(Script::default()).await;
    let read = login(&site, "tok-read");
    let admin = login(&site, "tok-admin");

    let (_, _, html) = get(&site, Some(&read), "/apps/web").await;
    assert!(
        !html.contains("Access log") && !html.contains("/access"),
        "{html}"
    );
    let (_, headers, html) = get(&site, Some(&admin), "/apps/web").await;
    assert!(html.contains("Access log") && html.contains("hx-get=\"/apps/web/access\""));
    assert!(!html.contains("sse-connect"), "{html}");
    assert_page_is_clean("/apps/web", &headers, &html);
    // Opening the page (as either user) asked the daemon for no stream.
    {
        let seen = site.daemon.seen.lock().unwrap();
        assert!(
            seen.iter()
                .all(|s| !s.path.ends_with("/access") && !s.path.ends_with("/logs")),
            "{:?}",
            seen.iter().map(|s| &s.path).collect::<Vec<_>>()
        );
    }

    // A read session is refused the fragment and the stream alike.
    for path in ["/apps/web/access", "/apps/web/access/stream"] {
        let (status, headers, html) = get(&site, Some(&read), path).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(html.contains("No access"), "{html}");
        assert_page_is_clean(path, &headers, &html);
    }
}

#[tokio::test]
async fn the_fragment_carries_the_reencoded_filter_and_a_bad_one_is_refused_without_echo() {
    let site = site(Script::default()).await;
    let admin = login(&site, "tok-admin");

    // A form sends blank filters as empty values; the path arrives percent-encoded.
    let (status, headers, html) = get(
        &site,
        Some(&admin),
        "/apps/web/access?status=5xx&method=&path=%2Fapi&host=",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(
        html.contains(
            "sse-connect=\"/apps/web/access/stream?follow=true&#38;status=5xx&#38;path=/api\""
        ),
        "{html}"
    );
    assert_page_is_clean("/apps/web/access", &headers, &html);

    // Browser-chosen follow/since are replaced, never forwarded.
    let (_, _, html) = get(&site, Some(&admin), "/apps/web/access?follow=false&since=5").await;
    assert!(html.contains("stream?follow=true\""), "{html}");

    for bad in [
        "status=%3Cscript%3Ealert(1)%3C/script%3E",
        "status=20",
        "method=get",
        "path=api",
        "path=%2Fa%26status%3D500",
        "host=Example.COM",
        "evil=1",
        "status=2xx&status=3xx",
        "tail=5000",
        &format!("path=%2F{}", "a".repeat(2000)),
    ] {
        let (status, headers, html) =
            get(&site, Some(&admin), &format!("/apps/web/access?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert!(html.contains("filter is not valid"), "{html}");
        for echoed in ["script", "=20", "evil", "Example", "aaaa"] {
            assert!(!html.contains(echoed), "{bad} echoed {echoed}: {html}");
        }
        assert_page_is_clean("/apps/web/access", &headers, &html);
        // The stream refuses it as well, before it asks the daemon for anything.
        let (status, ..) = get(
            &site,
            Some(&admin),
            &format!("/apps/web/access/stream?{bad}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert!(access_opens(&site).is_empty());
    assert_eq!(site.state.streams.open_streams(), 0);
}

#[tokio::test]
async fn the_daemon_gets_only_the_reencoded_query_with_follow() {
    let site = site(Script::default()).await;
    let admin = login(&site, "tok-admin");
    let response = open_stream(
        &site,
        &admin,
        "/apps/web/access/stream?since=1&follow=false&status=5xx&path=/api&host=&method=POST",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let text = read_until(&mut body, "index.html", WAIT).await.unwrap();
    assert!(text.contains("event: rows"), "{text}");
    let opens = access_opens(&site);
    assert_eq!(opens.len(), 1);
    assert_eq!(bearer(&opens[0]), "tok-admin");
    assert_eq!(
        opens[0].query.as_deref(),
        Some("follow=true&tail=100&status=5xx&method=POST&path=%2Fapi")
    );

    // An explicit tail is kept (bounded by the parser), without a filter nothing else is sent.
    let response = open_stream(&site, &admin, "/apps/web/access/stream?tail=7", None).await;
    let mut body2 = response.into_body();
    read_until(&mut body2, "index.html", WAIT).await.unwrap();
    assert_eq!(
        access_opens(&site)[1].query.as_deref(),
        Some("follow=true&tail=7")
    );
}

#[tokio::test]
async fn hostile_access_entries_render_safely() {
    let hostile = vec![
        AccessFrame::Entry(entry(
            "/<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        )),
        AccessFrame::Entry(entry(
            "/ansi\x1b[31mred\x1b[0m",
            "bidi \u{202e}evil\u{2066}x",
        )),
        AccessFrame::Entry(entry("/tab\tand\nnewline\0nul", &"U".repeat(10_000))),
        AccessFrame::Entry(AccessEntry {
            status: 503,
            request_time: f64::from(u16::MAX),
            method: "M".repeat(100),
            remote_addr: "\"><b>".into(),
            ..entry("/last", "end-marker")
        }),
    ];
    let site = site(Script {
        access: vec![(hostile, true)],
        ..Script::default()
    })
    .await;
    let admin = login(&site, "tok-admin");
    let mut body = open_stream(&site, &admin, "/apps/web/access/stream", None)
        .await
        .into_body();
    let text = read_until(&mut body, "end-marker", WAIT).await.unwrap();
    assert!(!text.contains("<script>") && !text.contains("<img") && !text.contains("<b>"));
    for c in ['\u{1b}', '\u{202e}', '\u{2066}', '\0', '\t'] {
        assert!(!text.contains(c), "{c:?} in {text:?}");
    }
    assert!(!text.contains(&"U".repeat(201)));
    insta::assert_snapshot!("hostile_access_entries", text);
}

#[tokio::test]
async fn access_streams_share_the_session_limit() {
    let site = site(Script::default()).await;
    let admin = login(&site, "tok-admin");
    let mut held = Vec::new();
    for _ in 0..weglarka_panel::live::MAX_STREAMS_PER_SESSION {
        let r = open_stream(&site, &admin, "/apps/web/access/stream", None).await;
        assert_eq!(r.status(), StatusCode::OK);
        held.push(r);
    }
    let r = open_stream(&site, &admin, "/apps/web/access/stream", None).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    // The refused one never reached the daemon.
    assert_eq!(
        access_opens(&site).len(),
        weglarka_panel::live::MAX_STREAMS_PER_SESSION
    );
    drop(held);
}

#[tokio::test]
async fn token_expiry_resumes_the_access_log_since_the_last_entry() {
    let site = site(Script {
        access: vec![
            (
                vec![
                    AccessFrame::Entry(entry("/one", "a")),
                    AccessFrame::TokenExpired,
                ],
                false,
            ),
            (vec![AccessFrame::Entry(entry("/two", "b"))], true),
        ],
        ..Script::default()
    })
    .await;
    let admin = login(&site, "tok-admin");
    let mut body = open_stream(&site, &admin, "/apps/web/access/stream?status=2xx", None)
        .await
        .into_body();
    let text = read_until(&mut body, "/two", WAIT).await.unwrap();
    assert!(text.contains("/one"));
    let opens = access_opens(&site);
    assert_eq!(opens.len(), 2);
    assert_eq!(
        opens[0].query.as_deref(),
        Some("follow=true&tail=100&status=2xx")
    );
    let at = weglarka_api::parse_rfc3339(b"2026-10-31T12:00:00Z").unwrap();
    assert_eq!(
        opens[1].query.as_deref(),
        Some(
            format!(
                "follow=true&since={}.{:09}&status=2xx",
                at.as_secs(),
                at.subsec_nanos()
            )
            .as_str()
        )
    );
}

#[tokio::test]
async fn an_access_log_error_is_shown_sanitized_and_ends_the_stream() {
    let site = site(Script {
        access: vec![(vec![AccessFrame::Error("nginx <log> gone".into())], false)],
        ..Script::default()
    })
    .await;
    let admin = login(&site, "tok-admin");
    let mut body = open_stream(&site, &admin, "/apps/web/access/stream", None)
        .await
        .into_body();
    let text = read_until(&mut body, "event: done", WAIT).await.unwrap();
    assert!(
        text.contains("event: status") && text.contains("nginx &lt;log&gt; gone"),
        "{text}"
    );
}
