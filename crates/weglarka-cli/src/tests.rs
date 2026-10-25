//! Tests: the client against a mock server (unix socket), preflight on a fake host, exit codes.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use clap::Parser as _;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use weglarka_api::{
    ApiError, CheckStatus, ConfigMountStatus, ConfigMountView, DeployOutcome, DeployResponse,
    DoctorCheck, DoctorReport, ErrorCode, NotifyStatusResponse, PruneImagesResponse, PrunedImage,
    ReloadAction, ReloadResponse, RuntimeState, SetSecretRequest, ShowAppResponse,
    UpdateAppResponse, endpoints,
};
use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::HostConfig;

use crate::cli::{AddArgs, ReloadArgs, RemoveArgs, SecretRemoveArgs, StartStopArgs};
use crate::client::{ApiClient, expand_path};
use crate::commands::{
    apps_reload, apps_remove, build_spec, notify_status, notify_test, read_secret_value,
    remove_dry_run, remove_query, remove_suffix, render_notify_status, render_reload, render_show,
    secret_remove_dry_run, secrets_remove,
};
use crate::error::{CliError, Kind, exit};
use crate::preflight::host::{CmdOutput, FileKind};
use crate::preflight::testing::FakeHost;
use crate::preflight::{Context, all_checks, render, run_checks};
use crate::settings::Overrides;
use crate::update::{apply_flags, apps_start, apps_stop, render_change, runtime_label};

// ---------- mock server on a unix socket ----------

#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) path: String,
    /// Query string without the leading `?` (`None` when the request had none).
    pub(crate) query: Option<String>,
    host: Option<String>,
    pub(crate) body: String,
}

pub(crate) struct Mock {
    pub(crate) socket: PathBuf,
    pub(crate) seen: Arc<Mutex<Vec<Seen>>>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

static N: AtomicU32 = AtomicU32::new(0);

/// `reply(method, path) -> (status, body)`.
pub(crate) async fn mock(
    reply: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
) -> Mock {
    // Short path: the sun_path limit (~104 B on macOS).
    let socket = std::env::temp_dir().join(format!(
        "wgl-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let reply = Arc::new(reply);
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (reply, seen) = (reply.clone(), seen2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (reply, seen) = (reply.clone(), seen.clone());
                    async move {
                        let method = req.method().to_string();
                        let path = req.uri().path().to_owned();
                        let query = req.uri().query().map(str::to_owned);
                        let host = req
                            .headers()
                            .get("host")
                            .map(|h| h.to_str().unwrap().to_owned());
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        seen.lock().unwrap().push(Seen {
                            method: method.clone(),
                            path: path.clone(),
                            query,
                            host,
                            body: String::from_utf8_lossy(&body).into_owned(),
                        });
                        let (status, body) = reply(&method, &path);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Mock { socket, seen }
}

fn api_err(code: ErrorCode, msg: &str) -> String {
    serde_json::to_string(&ApiError {
        code,
        message: msg.into(),
    })
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn client_retries_busy_until_the_daemon_accepts() {
    let calls = Arc::new(AtomicU32::new(0));
    let calls2 = calls.clone();
    let m = mock(move |_, _| {
        if calls2.fetch_add(1, Ordering::SeqCst) < 2 {
            (
                503,
                api_err(ErrorCode::Busy, "daemon is busy (deploy in progress)"),
            )
        } else {
            (204, String::new())
        }
    })
    .await;
    let c = ApiClient::new(&m.socket);
    c.call_empty(endpoints::APPS_REMOVE, &[("name", "ntfy")])
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(
        m.seen
            .lock()
            .unwrap()
            .iter()
            .all(|s| s.path == "/v1/apps/ntfy")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn client_does_not_retry_other_errors() {
    let calls = Arc::new(AtomicU32::new(0));
    let calls2 = calls.clone();
    let m = mock(move |_, _| {
        calls2.fetch_add(1, Ordering::SeqCst);
        (409, api_err(ErrorCode::Conflict, "conflict"))
    })
    .await;
    let c = ApiClient::new(&m.socket);
    let e = c
        .call_empty(endpoints::APPS_REMOVE, &[("name", "ntfy")])
        .await
        .unwrap_err();
    assert!(!e.is_busy());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn client_sends_contract_path_and_host_and_parses_json() {
    let m = mock(|_, _| {
        (
            200,
            serde_json::to_string(&DeployResponse {
                outcome: DeployOutcome::Unchanged,
                generation: 3,
                digest: None,
            })
            .unwrap(),
        )
    })
    .await;
    let c = ApiClient::new(&m.socket);
    let r: DeployResponse = c
        .call(
            endpoints::APPS_DEPLOY,
            &[("name", "ntfy")],
            Some(&weglarka_api::DeployRequest { image_ref: None }),
        )
        .await
        .unwrap();
    assert_eq!(r.generation, 3);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/apps/ntfy/deploy");
    assert_eq!(seen[0].host.as_deref(), Some("weglarka"));
}

#[tokio::test(flavor = "current_thread")]
async fn api_errors_map_to_exit_codes() {
    for (code, want) in [
        (ErrorCode::NotFound, exit::NOT_FOUND),
        (ErrorCode::AlreadyExists, exit::CONFLICT),
        (ErrorCode::Conflict, exit::CONFLICT),
        (ErrorCode::InvalidRequest, exit::INVALID_REQUEST),
        (ErrorCode::Busy, exit::CONFLICT),
        (ErrorCode::Internal, exit::INTERNAL),
    ] {
        let m = mock(move |_, _| (code.http_status(), api_err(code, "boom"))).await;
        let err = ApiClient::new(&m.socket)
            .with_busy_wait(std::time::Duration::ZERO)
            .call::<DoctorReport>(endpoints::DOCTOR, &[], None::<&()>)
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), want, "{code:?}");
        assert_eq!(err.message, "boom");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn empty_204_and_secret_body() {
    let m = mock(|method, _| {
        if method == "DELETE" {
            (204, String::new())
        } else {
            (200, "{}".into())
        }
    })
    .await;
    let c = ApiClient::new(&m.socket);
    c.call_empty(endpoints::APPS_REMOVE, &[("name", "x")])
        .await
        .unwrap();
    let _ = c
        .call::<serde_json::Value>(
            endpoints::SECRETS_SET,
            &[("name", "x"), ("secret", "cfg")],
            Some(&SetSecretRequest {
                value: "s3cr3t".into(),
            }),
        )
        .await;
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[1].method, "PUT");
    assert_eq!(seen[1].path, "/v1/apps/x/secrets/cfg");
    assert_eq!(seen[1].body, r#"{"value":"s3cr3t"}"#);
}

#[tokio::test(flavor = "current_thread")]
async fn missing_socket_is_unreachable_with_hint() {
    let err = ApiClient::new("/nonexistent/wgl.sock")
        .call::<DoctorReport>(endpoints::DOCTOR, &[], None::<&()>)
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::Unreachable);
    assert_eq!(err.exit_code(), exit::UNREACHABLE);
    assert!(err.hint.unwrap().contains("--socket"));
}

#[test]
fn expand_path_substitutes() {
    assert_eq!(
        expand_path(endpoints::SECRETS_SET, &[("name", "a"), ("secret", "b")]),
        "/v1/apps/a/secrets/b"
    );
}

// ---------- secrets ----------

#[test]
fn secret_value_rules() {
    let read = |input: &[u8], tty, raw| read_secret_value(None, &mut &input[..], tty, raw);
    assert_eq!(read(b"abc\n", false, false).unwrap(), "abc");
    assert_eq!(read(b"abc\r\n", false, false).unwrap(), "abc");
    assert_eq!(read(b"abc\n", false, true).unwrap(), "abc\n");
    assert_eq!(read(b"abc\n\n", false, false).unwrap(), "abc\n");
    assert_eq!(read(b"x", true, false).unwrap_err().kind, Kind::Usage);
    assert!(read(b"\n", false, false).is_err());
    assert!(read(&[0xff, 0xfe], false, false).is_err());
}

#[test]
fn error_envelope_is_stable() {
    let e = CliError::from_api(ErrorCode::NotFound, "no app".into());
    insta::assert_snapshot!(serde_json::to_string_pretty(&e.envelope()).unwrap());
}

#[test]
fn clap_parses_secret_without_value_argument() {
    use clap::Parser;
    let cli =
        crate::cli::Cli::try_parse_from(["weglarka", "secrets", "set", "app", "cfg", "hunter2"]);
    assert!(cli.is_err(), "wartość jako argument musi być odrzucona");
}

// ---------- preflight ----------

const CONFIG: &str = r#"
[runtime]
user = "weglarka"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
traefik_dynamic_file = "/data/traefik/weglarka.yml"
[admin]
socket = "/run/user/1001/weglarka/admin.sock"
[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"
"#;

/// `edge` host (issue #95): two publishes, no Traefik. High ports keep it independent of the
/// privileged-port opt-in; the TLS directory lives under the state dir's `nginx/`.
const EDGE_CONFIG: &str = r#"
[runtime]
user = "weglarka"
[ingress]
mode = "edge"
bind = "0.0.0.0:18080"
https_bind = "0.0.0.0:18443"
[admin]
socket = "/run/user/1001/weglarka/admin.sock"
[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"
"#;

/// A healthy edge host: the webhook domain's certificate is in place and the firewall/sysctl facts
/// are fine.
fn edge_host() -> FakeHost {
    FakeHost::healthy()
        .stat(
            "/etc/weglarka/nginx/tls/weglarka.example.eu.crt",
            FileKind::File,
            0o600,
            1001,
            1001,
        )
        .stat(
            "/etc/weglarka/nginx/tls/weglarka.example.eu.key",
            FileKind::File,
            0o600,
            1001,
            1001,
        )
        .file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "1024\n")
}

fn report(host: &FakeHost, config: Option<&str>) -> DoctorReport {
    let cfg = config
        .map(|c| HostConfig::from_toml_str(c).map_err(|e| e.to_string()))
        .unwrap_or_else(|| Err("cannot read config /etc/weglarka/weglarka.toml: not found".into()));
    let cx = Context::build(host, "/etc/weglarka/weglarka.toml".into(), cfg, None);
    run_checks(&cx, &all_checks())
}

#[test]
fn preflight_healthy_host() {
    let r = report(&FakeHost::healthy(), Some(CONFIG));
    insta::assert_snapshot!(render(&r));
    assert_eq!(r.exit_code(), 0);
}

#[test]
fn preflight_edge_host() {
    let r = report(&edge_host(), Some(EDGE_CONFIG));
    insta::assert_snapshot!(render(&r));
    assert_eq!(r.exit_code(), 0);
    let ids: Vec<_> = r.checks.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"ingress.tls"), "{ids:?}");
    assert!(!ids.contains(&"ingress.traefik_file"), "{ids:?}");
    assert!(
        !ids.contains(&"ingress.privileged_ports"),
        "high ports need no sysctl: {ids:?}"
    );
}

#[test]
fn preflight_edge_reports_missing_certificates_as_a_warning() {
    let r = report(&FakeHost::healthy(), Some(EDGE_CONFIG));
    let tls = r
        .checks
        .iter()
        .find(|c| c.id == "ingress.tls")
        .expect("ingress.tls");
    assert_eq!(tls.status, weglarka_api::CheckStatus::Warn, "{tls:?}");
    assert!(
        tls.message.contains("weglarka.example.eu"),
        "names the missing domain: {}",
        tls.message
    );
    assert!(tls.hint.is_some(), "a warning carries a fix");
}

#[test]
fn preflight_edge_accepts_a_wildcard_pair_for_the_domains_it_covers() {
    // `weglarka.example.eu` has no pair of its own, but `[acme.dns]` lists `example.eu` and the
    // wildcard pair `_wildcard.example.eu` is on disk and readable (issue #97).
    let cfg = format!(
        "{EDGE_CONFIG}\n[acme]\naccept_terms = true\n\n[acme.dns]\nprovider = \"cloudflare\"\n\
         token_file = \"/var/lib/weglarka/cf-token\"\nwildcards = [\"example.eu\"]\n"
    );
    let with_wildcard = FakeHost::healthy()
        .stat(
            "/etc/weglarka/nginx/tls/_wildcard.example.eu.crt",
            FileKind::File,
            0o600,
            1001,
            1001,
        )
        .stat(
            "/etc/weglarka/nginx/tls/_wildcard.example.eu.key",
            FileKind::File,
            0o600,
            1001,
            1001,
        );
    let status = |host: &FakeHost| {
        report(host, Some(&cfg))
            .checks
            .into_iter()
            .find(|c| c.id == "ingress.tls")
            .expect("ingress.tls")
            .status
    };
    assert_eq!(status(&with_wildcard), weglarka_api::CheckStatus::Ok);
    // Without the wildcard pair on disk the domain is missing a certificate again.
    assert_eq!(
        status(&FakeHost::healthy()),
        weglarka_api::CheckStatus::Warn
    );
}

#[test]
fn preflight_edge_requires_the_sysctl_for_privileged_ports() {
    let cfg = EDGE_CONFIG
        .replace(
            "user = \"weglarka\"",
            "user = \"weglarka\"\nallow_privileged_host_ports = true",
        )
        .replace("0.0.0.0:18080", "0.0.0.0:80")
        .replace("0.0.0.0:18443", "0.0.0.0:443");
    let status = |sysctl: &str| {
        let host = edge_host().file("/proc/sys/net/ipv4/ip_unprivileged_port_start", sysctl);
        report(&host, Some(&cfg))
            .checks
            .into_iter()
            .find(|c| c.id == "ingress.privileged_ports")
            .unwrap_or_else(|| panic!("brak ingress.privileged_ports dla {sysctl:?}"))
            .status
    };
    assert_eq!(status("1024\n"), weglarka_api::CheckStatus::Fail);
    assert_eq!(status("0\n"), weglarka_api::CheckStatus::Ok);
}

#[test]
fn preflight_broken_host() {
    let mut h = FakeHost::healthy()
        .file("/etc/subuid", "weglarka:165536:1000\n")
        .stat("/var/lib/systemd/linger/weglarka", FileKind::File, 0, 0, 0)
        .ping(Some("5.7.0"))
        .stat("/data/traefik/weglarka.yml", FileKind::File, 0o644, 0, 0)
        .stat("/etc/weglarka/secrets.toml", FileKind::File, 0o644, 0, 0)
        .cmd(
            "ip -j addr show",
            r#"[{"addr_info":[{"local":"10.0.0.2"}]}]"#,
        );
    h.stats
        .remove(&PathBuf::from("/var/lib/systemd/linger/weglarka"));
    h.commands.remove("pasta --version");
    h.commands.insert(
        "apt-cache policy podman".into(),
        CmdOutput {
            success: true,
            stdout: "podman:\n  Installed: 4.9.3\n  Version table:\n *** 4.9.3 500\n        500 http://archive.ubuntu.com/ubuntu noble Packages\n".into(),
            stderr: String::new(),
        },
    );
    let r = report(&h, Some(CONFIG));
    insta::assert_snapshot!(render(&r));
    assert_eq!(r.exit_code(), 2);
}

#[test]
fn preflight_reports_a_newer_apps_schema_instead_of_an_unknown_field() {
    // The host-port check reads apps.toml itself; a file written by a newer Węglarka must be
    // reported as a schema mismatch, not as a typo (ADR 0023).
    let newer = weglarka_core::state::SCHEMA_VERSION + 1;
    let h = FakeHost::healthy().file(
        "/etc/weglarka/apps.toml",
        &format!("schema_version = {newer}\n[apps.a]\nimage = \"x:1\"\nfuture_field = 1\n"),
    );
    let r = report(&h, Some(CONFIG));
    let check = r
        .checks
        .iter()
        .find(|c| c.id == "apps.host_ports_free")
        .expect("the host-port check applies with a config");
    assert_eq!(check.status, CheckStatus::Fail);
    assert!(
        check.message.contains(&format!("schema version {newer}")),
        "{}",
        check.message
    );
    assert!(
        check.hint.as_deref().unwrap_or_default().contains("newer"),
        "{:?}",
        check.hint
    );
}

#[test]
fn preflight_without_config_or_user_degrades_gracefully() {
    let h = FakeHost::default();
    let r = report(&h, None);
    insta::assert_snapshot!(render(&r));
    assert_eq!(r.exit_code(), 2);
}

#[test]
fn preflight_json_uses_api_types() {
    let r = report(&FakeHost::healthy(), Some(CONFIG));
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["checks"][0]["status"], "ok");
    let back: DoctorReport = serde_json::from_value(v).unwrap();
    assert_eq!(back, r);
}

#[test]
fn render_reports_info_checks_without_alarming() {
    let report = DoctorReport {
        checks: vec![DoctorCheck {
            id: "state.deploying".into(),
            status: CheckStatus::Info,
            message: "deploy w toku: ntfy (recreate)".into(),
            hint: None,
        }],
    };
    let text = render(&report);
    assert!(text.contains("[INFO] state.deploying"), "{text}");
    assert!(text.contains("0 ok, 1 info, 0 warn, 0 fail"), "{text}");
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn edge_mode_skips_traefik_check_and_openrc_skips_linger() {
    let cfg = EDGE_CONFIG.replace("\n[webhook]", "\n[platform]\nkind = \"openrc\"\n[webhook]");
    let r = report(&edge_host(), Some(&cfg));
    let ids: Vec<_> = r.checks.iter().map(|c| c.id.as_str()).collect();
    assert!(!ids.contains(&"ingress.traefik_file"), "{ids:?}");
    assert!(!ids.contains(&"runtime.linger"), "{ids:?}");
    assert!(ids.contains(&"ingress.tls"), "{ids:?}");
}

// ---------- new host checks (devops) ----------

fn status_of(host: &FakeHost, id: &str) -> weglarka_api::CheckStatus {
    report(host, Some(CONFIG))
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("brak sprawdzenia {id}"))
        .status
}

#[test]
fn subid_thresholds_ok_warn_fail() {
    use weglarka_api::CheckStatus::*;
    let with = |n: u64| FakeHost::healthy().file("/etc/subuid", &format!("weglarka:165536:{n}\n"));
    assert_eq!(status_of(&with(1_000_000), "runtime.subuid"), Ok);
    assert_eq!(status_of(&with(999_999), "runtime.subuid"), Warn);
    assert_eq!(status_of(&with(65_536), "runtime.subuid"), Warn);
    assert_eq!(status_of(&with(65_535), "runtime.subuid"), Fail);
}

#[test]
fn apparmor_userns_cases() {
    use weglarka_api::CheckStatus::*;
    let id = "runtime.apparmor_userns";
    assert_eq!(status_of(&FakeHost::healthy(), id), Ok);
    let mut h = FakeHost::healthy();
    h.files.remove(&PathBuf::from(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    ));
    assert_eq!(status_of(&h, id), Ok, "brak AppArmor = skip");
    let h = FakeHost::healthy().file(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
        "0\n",
    );
    assert_eq!(status_of(&h, id), Ok);
    let h = FakeHost::healthy().file("/sys/kernel/security/apparmor/profiles", "crun (enforce)\n");
    assert_eq!(status_of(&h, id), Fail);
    // profiles unreadable for non-root → warn
    let mut h = FakeHost::healthy();
    h.files
        .remove(&PathBuf::from("/sys/kernel/security/apparmor/profiles"));
    assert_eq!(status_of(&h, id), Warn);
}

fn tcp_line(hex_addr: &str, port: u16, uid: u32) -> String {
    format!(
        "   0: {hex_addr}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid:5}        0 1 1 0\n"
    )
}

#[test]
fn bind_free_cases() {
    use crate::preflight::testing::PROC_NET_TCP_HEADER as H;
    use weglarka_api::CheckStatus::*;
    let id = "ingress.bind_free";
    assert_eq!(status_of(&FakeHost::healthy(), id), Ok);
    // 172.17.0.1 = 0x010011AC in little-endian hex "010011AC"
    let ours = format!("{H}{}", tcp_line("010011AC", 8080, 1001));
    assert_eq!(
        status_of(&FakeHost::healthy().file("/proc/net/tcp", &ours), id),
        Ok
    );
    let traefik = format!("{H}{}", tcp_line("00000000", 8080, 0));
    assert_eq!(
        status_of(&FakeHost::healthy().file("/proc/net/tcp", &traefik), id),
        Fail
    );
    let other_port = format!("{H}{}", tcp_line("00000000", 8081, 0));
    assert_eq!(
        status_of(&FakeHost::healthy().file("/proc/net/tcp", &other_port), id),
        Ok
    );
    let other_ip = format!("{H}{}", tcp_line("0100007F", 8080, 0));
    assert_eq!(
        status_of(&FakeHost::healthy().file("/proc/net/tcp", &other_ip), id),
        Ok,
        "inny adres IPv4 nie koliduje"
    );
    let mut h = FakeHost::healthy();
    h.files.remove(&PathBuf::from("/proc/net/tcp"));
    assert_eq!(status_of(&h, id), Warn);
}

/// A healthy host with `apps.toml` at the state path derived from [`CONFIG`].
fn host_ports_host(apps: &str) -> FakeHost {
    FakeHost::healthy().file("/etc/weglarka/apps.toml", apps)
}

#[test]
fn host_ports_free_cases() {
    use crate::preflight::testing::PROC_NET_TCP_HEADER as H;
    use weglarka_api::CheckStatus::*;
    let id = "apps.host_ports_free";
    // No apps.toml: nothing to publish, nothing to check.
    assert_eq!(status_of(&FakeHost::healthy(), id), Ok);
    // apps.toml without host_ports.
    assert_eq!(
        status_of(&host_ports_host("[apps.a]\nimage = \"i\"\n"), id),
        Ok
    );
    let git = "[apps.git]\nimage = \"i\"\nhost_ports = [{ host = 2222, container = 22 }]\n";
    assert_eq!(status_of(&host_ports_host(git), id), Ok, "free port");
    // The runtime user's own socket (rootlessport of a running app) is not a collision.
    let ours = format!("{H}{}", tcp_line("0100007F", 2222, 1001));
    assert_eq!(
        status_of(&host_ports_host(git).file("/proc/net/tcp", &ours), id),
        Ok
    );
    // Someone else holds the wildcard address.
    let wildcard = format!("{H}{}", tcp_line("00000000", 2222, 0));
    assert_eq!(
        status_of(&host_ports_host(git).file("/proc/net/tcp", &wildcard), id),
        Fail
    );
    // ... or the loopback address itself.
    let loopback = format!("{H}{}", tcp_line("0100007F", 2222, 4242));
    assert_eq!(
        status_of(&host_ports_host(git).file("/proc/net/tcp", &loopback), id),
        Fail
    );
    // A different specific address is a different socket.
    let other_ip = format!("{H}{}", tcp_line("010011AC", 2222, 0));
    assert_eq!(
        status_of(&host_ports_host(git).file("/proc/net/tcp", &other_ip), id),
        Ok
    );
    // Privileged port without the explicit host opt-in.
    let ssh = "[apps.git]\nimage = \"i\"\nhost_ports = [{ host = 22, container = 22 }]\n";
    assert_eq!(status_of(&host_ports_host(ssh), id), Fail);
    let allowed = CONFIG.replace(
        "user = \"weglarka\"",
        "user = \"weglarka\"\nallow_privileged_host_ports = true",
    );
    let r = report(&host_ports_host(ssh), Some(&allowed));
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.id == id)
            .expect("check present")
            .status,
        Ok
    );
    // Two apps publishing the same host socket.
    let conflict = "[apps.a]\nimage = \"i\"\nhost_ports = [{ host = 2222, container = 22 }]\n\
                    [apps.b]\nimage = \"j\"\nhost_ports = [{ host = 2222, container = 22 }]\n";
    assert_eq!(status_of(&host_ports_host(conflict), id), Fail);
    // An IPv6 bind cannot be matched against /proc/net/tcp; it is reported as skipped, not failed.
    let v6 =
        "[apps.git]\nimage = \"i\"\nhost_ports = [{ host = 2222, container = 22, ip = \"::1\" }]\n";
    let r = report(&host_ports_host(v6), Some(CONFIG));
    let check = r.checks.iter().find(|c| c.id == id).expect("check present");
    assert_eq!(check.status, Ok);
    assert!(check.message.contains("IPv6"), "{}", check.message);
    // Unparseable apps.toml.
    assert_eq!(status_of(&host_ports_host("[apps.a]\nimage = "), id), Fail);
    // /proc/net/tcp unavailable.
    let mut h = host_ports_host(git);
    h.files.remove(&PathBuf::from("/proc/net/tcp"));
    assert_eq!(status_of(&h, id), Warn);
}

const POLICY: &str = r#"{"allowed_domains":["nz.example.eu","weglarka.example.eu"]}"#;

fn sync_host(unit_state: &str, apps: Option<&str>) -> FakeHost {
    let mut h = FakeHost::healthy()
        .file("/etc/weglarka/traefik-policy.json", POLICY)
        .cmd("systemctl is-active weglarka-traefik-sync.path", unit_state);
    if let Some(a) = apps {
        h = h.file("/etc/weglarka/apps.toml", a);
    }
    h
}

#[test]
fn traefik_sync_cases() {
    use weglarka_api::CheckStatus::*;
    let id = "ingress.traefik_sync";
    let app = |d: &str| format!("[apps.a]\nimage = \"x\"\ndomains = [\"{d}\"]\n");
    // no policy = sync not used
    assert_eq!(status_of(&FakeHost::healthy(), id), Ok);
    assert_eq!(status_of(&sync_host("active\n", None), id), Ok);
    assert_eq!(
        status_of(&sync_host("active\n", Some(&app("NZ.example.eu"))), id),
        Ok
    );
    assert_eq!(
        status_of(&sync_host("active\n", Some(&app("evil.example.eu"))), id),
        Warn
    );
    assert_eq!(status_of(&sync_host("inactive\n", None), id), Fail);
    // no systemctl
    let mut h = sync_host("active\n", None);
    h.commands.clear();
    assert_eq!(status_of(&h, id), Warn);
    // policy without an allowlist
    let h = sync_host("active\n", None).file("/etc/weglarka/traefik-policy.json", "{}");
    assert_eq!(status_of(&h, id), Warn);
}

#[test]
fn traefik_sync_only_for_behind_on_systemd() {
    let edge = CONFIG.replace("behind", "edge");
    let r = report(&sync_host("active\n", None), Some(&edge));
    assert!(r.checks.iter().all(|c| c.id != "ingress.traefik_sync"));
    let openrc = CONFIG.replace("\n[webhook]", "\n[platform]\nkind = \"openrc\"\n[webhook]");
    let r = report(&sync_host("active\n", None), Some(&openrc));
    assert!(r.checks.iter().all(|c| c.id != "ingress.traefik_sync"));
}

// ---------- apps lifecycle: `start = false`, `apps start` / `apps stop` ----------

/// `apps add` flags as parsed from the command line.
fn add_args(extra: &[&str]) -> AddArgs {
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        a: AddArgs,
    }
    let mut argv = vec!["add", "ntfy", "ghcr.io/x/ntfy:latest"];
    argv.extend_from_slice(extra);
    Add::try_parse_from(argv).unwrap().a
}

/// `apps update` flags as parsed from the command line.
fn update_args(extra: &[&str]) -> crate::update::UpdateArgs {
    #[derive(clap::Parser)]
    struct Up {
        #[command(flatten)]
        a: crate::update::UpdateArgs,
    }
    let mut argv = vec!["up", "ntfy"];
    argv.extend_from_slice(extra);
    Up::try_parse_from(argv).unwrap().a
}

fn app_spec(start: bool) -> AppSpec {
    let mut spec: AppSpec = toml::from_str(
        r#"
image = "ghcr.io/x/ntfy:latest"
domains = ["ntfy.example.eu"]
port = 8085
volumes = [{ name = "data", target = "/var/lib/ntfy" }]
"#,
    )
    .unwrap();
    spec.start = start;
    spec
}

fn show_app(start: bool) -> ShowAppResponse {
    ShowAppResponse {
        name: InstanceName::new("ntfy").unwrap(),
        spec: app_spec(start),
        state: Default::default(),
        runtime: if start {
            RuntimeState::Running
        } else {
            RuntimeState::NotStarted
        },
        configs: None,
        host_mounts: None,
    }
}

fn update_response(start: bool, outcome: DeployOutcome) -> String {
    serde_json::to_string(&UpdateAppResponse {
        app: show_app(start),
        deploy: Some(DeployResponse {
            outcome,
            generation: 2,
            digest: None,
        }),
    })
    .unwrap()
}

fn overrides(m: &Mock) -> Overrides {
    Overrides {
        config: None,
        socket: Some(m.socket.clone()),
    }
}

#[test]
fn add_no_start_builds_a_provision_only_spec() {
    let spec = build_spec(&add_args(&["--no-start"])).unwrap();
    assert!(!spec.start);
    let body = serde_json::to_value(weglarka_api::AddAppRequest {
        name: InstanceName::new("ntfy").unwrap(),
        spec,
    })
    .unwrap();
    assert_eq!(body["spec"]["start"], serde_json::json!(false));

    // Without the flag the app runs; the default `start = true` is not serialized.
    let running = build_spec(&add_args(&[])).unwrap();
    assert!(running.start);
    let body = serde_json::to_value(running).unwrap();
    assert!(body.get("start").is_none(), "{body}");
}

#[test]
fn add_accepts_host_ports() {
    let spec = build_spec(&add_args(&[
        "--host-port",
        "2222:22",
        "--host-port",
        "0.0.0.0:8088:80",
    ]))
    .unwrap();
    let ports: Vec<_> = spec
        .host_ports
        .iter()
        .map(|p| (p.host, p.container, p.bind_ip().to_owned()))
        .collect();
    assert_eq!(
        ports,
        [
            (2222, 22, "127.0.0.1".to_owned()),
            (8088, 80, "0.0.0.0".to_owned())
        ]
    );
    // Same rules as the other spec flags: incompatible with --spec.
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        _a: AddArgs,
    }
    assert!(
        Add::try_parse_from([
            "add",
            "ntfy",
            "img",
            "--host-port",
            "2222:22",
            "--spec",
            "f"
        ])
        .is_err()
    );
}

#[test]
fn add_accepts_depends_on() {
    let spec = build_spec(&add_args(&["--depends-on", "db", "--depends-on", "cache"])).unwrap();
    let deps: Vec<_> = spec.depends_on.iter().map(ToString::to_string).collect();
    assert_eq!(deps, ["db", "cache"]);
    // Same rules as the other spec flags: incompatible with --spec.
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        _a: AddArgs,
    }
    assert!(
        Add::try_parse_from(["add", "ntfy", "img", "--depends-on", "db", "--spec", "f"]).is_err()
    );
    // A name that is not a valid app name is a usage error, not a silent no-op.
    assert!(Add::try_parse_from(["add", "ntfy", "img", "--depends-on", "DB"]).is_err());
}

#[test]
fn add_accepts_max_body_size() {
    let spec = build_spec(&add_args(&["--max-body-size", "4g"])).unwrap();
    assert_eq!(spec.ingress.max_body_size.map(|l| l.bytes()), Some(4 << 30));
    assert!(
        build_spec(&add_args(&[]))
            .unwrap()
            .ingress
            .max_body_size
            .is_none()
    );
}

#[test]
fn add_accepts_streaming_paths() {
    let spec = build_spec(&add_args(&["--streaming-path", "/user/events"])).unwrap();
    assert_eq!(spec.ingress.streaming_paths, ["/user/events"]);
    assert!(!spec.ingress.streaming);
    assert!(build_spec(&add_args(&[])).unwrap().ingress.is_default());
}

#[test]
fn add_accepts_streaming() {
    let spec = build_spec(&add_args(&["--streaming"])).unwrap();
    assert!(spec.ingress.streaming);
    assert_eq!(
        spec.ingress.stream_timeout_secs,
        weglarka_core::app::AppIngress::DEFAULT_STREAM_TIMEOUT_SECS
    );
    // Without the flag the whole table stays out of the spec (and out of apps.toml).
    assert!(build_spec(&add_args(&[])).unwrap().ingress.is_default());
    // Same rules as the other spec flags: incompatible with --spec.
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        _a: AddArgs,
    }
    assert!(Add::try_parse_from(["add", "ntfy", "img", "--streaming", "--spec", "f"]).is_err());
}

#[test]
fn add_accepts_command_arguments() {
    let spec = build_spec(&add_args(&["--command", "serve", "--command=--no-log"])).unwrap();
    assert_eq!(spec.command, ["serve", "--no-log"]);
    // Without the flag the field stays out of the spec (and out of apps.toml).
    assert!(build_spec(&add_args(&[])).unwrap().command.is_empty());
    // Same rules as the other spec flags: incompatible with --spec.
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        _a: AddArgs,
    }
    assert!(
        Add::try_parse_from(["add", "ntfy", "img", "--command", "serve", "--spec", "f"]).is_err()
    );
    // The dash-leading form is parsed, the naive one is rejected by clap as an unknown flag.
    assert!(Add::try_parse_from(["add", "ntfy", "img", "--command", "-v"]).is_err());
}

#[test]
fn add_accepts_config_mounts_and_reload_signal() {
    let spec = build_spec(&add_args(&[
        "--config-mount",
        "prometheus/prometheus.yml:/etc/prometheus/prometheus.yml",
        "--config-mount",
        "prometheus/rules:/etc/prometheus/rules",
        "--reload-signal",
        "SIGHUP",
    ]))
    .unwrap();
    assert_eq!(spec.configs.len(), 2);
    assert_eq!(spec.configs[1].source, "prometheus/rules");
    assert_eq!(spec.configs[1].target, "/etc/prometheus/rules");
    assert_eq!(
        spec.reload_signal.as_deref(),
        Some("HUP"),
        "normalized to the name the engine sends"
    );
    // Without the flags the fields stay out of the spec (and out of apps.toml).
    let plain = build_spec(&add_args(&[])).unwrap();
    assert!(plain.configs.is_empty() && plain.reload_signal.is_none());
    // `none` clears them, like the other list flags.
    let cleared = build_spec(&add_args(&[
        "--config-mount",
        "none",
        "--reload-signal",
        "none",
    ]))
    .unwrap();
    assert!(cleared.configs.is_empty() && cleared.reload_signal.is_none());
    // Same rules as the other spec flags: incompatible with --spec.
    #[derive(clap::Parser)]
    struct Add {
        #[command(flatten)]
        _a: AddArgs,
    }
    assert!(
        Add::try_parse_from([
            "add",
            "ntfy",
            "img",
            "--config-mount",
            "app/config.yml:/etc/app.yml",
            "--spec",
            "f",
        ])
        .is_err()
    );
}

fn config_mounts() -> Vec<ConfigMountView> {
    vec![
        ConfigMountView {
            source: "prometheus/prometheus.yml".into(),
            target: "/etc/prometheus/prometheus.yml".into(),
            status: ConfigMountStatus::Ok,
            fingerprint: Some("3f2a1b9c".repeat(8)),
            detail: None,
        },
        ConfigMountView {
            source: "prometheus/rules".into(),
            target: "/etc/prometheus/rules".into(),
            status: ConfigMountStatus::Missing,
            fingerprint: None,
            detail: Some("no such file: /srv/config/prometheus/rules".into()),
        },
    ]
}

#[test]
fn show_renders_config_mounts_with_short_fingerprints_and_details() {
    let mut app = show_app(true);
    app.configs = Some(config_mounts());
    let out = render_show(&app);
    assert!(out.contains("[configs]"), "{out}");
    assert!(
        out.contains("prometheus/prometheus.yml -> /etc/prometheus/prometheus.yml  ok 3f2a1b9c"),
        "{out}"
    );
    assert!(
        out.contains(
            "prometheus/rules -> /etc/prometheus/rules  missing (no such file: \
             /srv/config/prometheus/rules)"
        ),
        "{out}"
    );
    assert!(
        !out.contains(&"3f2a1b9c".repeat(8)),
        "the fingerprint is abbreviated: {out}"
    );
    // No mounts in the response: no section at all (the daemon omits the field for such apps).
    assert!(!render_show(&show_app(true)).contains("[configs]"));
}

fn reload_response(action: ReloadAction) -> ReloadResponse {
    ReloadResponse {
        name: InstanceName::new("prometheus").unwrap(),
        action,
        signal: matches!(action, ReloadAction::Signalled).then(|| "HUP".to_owned()),
        configs: None,
    }
}

#[test]
fn reload_rendering_covers_every_action() {
    assert_eq!(
        render_reload(&reload_response(ReloadAction::Signalled)),
        "prometheus: signalled SIGHUP\n"
    );
    assert_eq!(
        render_reload(&reload_response(ReloadAction::Restarted)),
        "prometheus: restarted\n"
    );
    assert_eq!(
        render_reload(&reload_response(ReloadAction::Recreated)),
        "prometheus: recreated (same digest)\n"
    );
    // The response carries the mounts after the reload: print the same block as `apps show`.
    let mut with_configs = reload_response(ReloadAction::Signalled);
    with_configs.configs = Some(config_mounts());
    let out = render_reload(&with_configs);
    assert!(
        out.starts_with("prometheus: signalled SIGHUP\n[configs]\n"),
        "{out}"
    );
    assert!(out.contains("  ok 3f2a1b9c"), "{out}");
    assert!(out.contains("  missing (no such file"), "{out}");
}

#[test]
fn reload_flags_parse() {
    #[derive(clap::Parser)]
    struct W {
        #[command(flatten)]
        a: ReloadArgs,
    }
    let a = W::try_parse_from(["w", "prometheus"]).unwrap().a;
    assert_eq!(a.name, "prometheus");
    assert!(!a.recreate);
    assert!(
        W::try_parse_from(["w", "prometheus", "--recreate"])
            .unwrap()
            .a
            .recreate
    );
    // The instance name is still required.
    assert!(W::try_parse_from(["w"]).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn apps_reload_posts_the_reload_endpoint_and_the_recreate_flag() {
    for recreate in [false, true] {
        let action = if recreate {
            ReloadAction::Recreated
        } else {
            ReloadAction::Signalled
        };
        let response = serde_json::to_string(&reload_response(action)).unwrap();
        let m = mock(move |_, _| (200, response.clone())).await;
        let code = apps_reload(
            true,
            &overrides(&m),
            ReloadArgs {
                name: "prometheus".into(),
                recreate,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        {
            let seen = m.seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(
                (seen[0].method.as_str(), seen[0].path.as_str()),
                ("POST", "/v1/apps/prometheus/reload")
            );
            let body: weglarka_api::ReloadRequest = serde_json::from_str(&seen[0].body).unwrap();
            assert_eq!(body.recreate, recreate, "body {recreate:?}");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reload_of_a_stopped_app_hints_at_apps_start() {
    let m = mock(|_, _| (409, api_err(ErrorCode::Conflict, "app ntfy is not running"))).await;
    let err = apps_reload(
        false,
        &overrides(&m),
        ReloadArgs {
            name: "ntfy".into(),
            recreate: false,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFLICT);
    assert!(
        err.hint
            .as_deref()
            .unwrap_or_default()
            .contains("weglarka apps start ntfy"),
        "hint: {:?}",
        err.hint
    );
}

#[test]
fn update_flags_flip_start() {
    assert!(
        !apply_flags(app_spec(true), &update_args(&["--no-start"]))
            .unwrap()
            .start
    );
    assert!(
        apply_flags(app_spec(false), &update_args(&["--start"]))
            .unwrap()
            .start
    );

    #[derive(clap::Parser)]
    struct Up {
        #[command(flatten)]
        _a: crate::update::UpdateArgs,
    }
    assert!(Up::try_parse_from(["up", "ntfy", "--start", "--no-start"]).is_err());
    assert!(Up::try_parse_from(["up", "ntfy", "--start", "--spec", "f"]).is_err());
    assert!(Up::try_parse_from(["up", "ntfy", "--no-start", "--spec", "f"]).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn apps_start_puts_start_true_and_renders_the_deploy() {
    let get = serde_json::to_string(&show_app(false)).unwrap();
    let put = update_response(true, DeployOutcome::Deployed);
    let m = mock(move |method, _| match method {
        "GET" => (200, get.clone()),
        _ => (200, put.clone()),
    })
    .await;
    let code = apps_start(
        true,
        &overrides(&m),
        StartStopArgs {
            name: "ntfy".into(),
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    {
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("GET", "/v1/apps/ntfy")
        );
        assert_eq!(
            (seen[1].method.as_str(), seen[1].path.as_str()),
            ("PUT", "/v1/apps/ntfy")
        );
        // The whole spec travels (read-modify-write); only `start` flips.
        let req: weglarka_api::UpdateAppRequest = serde_json::from_str(&seen[1].body).unwrap();
        assert!(req.spec.start, "PUT must set start = true");
        assert_eq!(req.spec.domains, ["ntfy.example.eu"]);
        assert_eq!(req.spec.volumes, app_spec(false).volumes);
    }

    let rendered = render_change(
        "started",
        &UpdateAppResponse {
            app: show_app(true),
            deploy: Some(DeployResponse {
                outcome: DeployOutcome::Deployed,
                generation: 2,
                digest: None,
            }),
        },
        &crate::update::spec_diff(&app_spec(false), &app_spec(true)),
        "deploy: none\n",
    );
    assert!(rendered.starts_with("started ntfy\n"), "{rendered}");
    assert!(
        rendered.contains("deploy: Deployed (generation 2)"),
        "{rendered}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn apps_stop_puts_start_false_and_renders_provisioning() {
    let get = serde_json::to_string(&show_app(true)).unwrap();
    let put = update_response(false, DeployOutcome::Provisioned);
    let m = mock(move |method, _| match method {
        "GET" => (200, get.clone()),
        _ => (200, put.clone()),
    })
    .await;
    let code = apps_stop(
        true,
        &overrides(&m),
        StartStopArgs {
            name: "ntfy".into(),
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    {
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].method, "PUT");
        let body: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
        assert_eq!(body["spec"]["start"], serde_json::json!(false));
    }

    let rendered = render_change(
        "stopped",
        &UpdateAppResponse {
            app: show_app(false),
            deploy: Some(DeployResponse {
                outcome: DeployOutcome::Provisioned,
                generation: 3,
                digest: None,
            }),
        },
        &crate::update::spec_diff(&app_spec(true), &app_spec(false)),
        "deploy: none\n",
    );
    assert!(rendered.starts_with("stopped ntfy\n"), "{rendered}");
    assert!(
        rendered
            .contains("deploy: provisioned (start = false): no container started (generation 3)"),
        "{rendered}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn start_stop_noop_sends_nothing() {
    let get = serde_json::to_string(&show_app(true)).unwrap();
    let m = mock(move |_, _| (200, get.clone())).await;
    let code = apps_start(
        true,
        &overrides(&m),
        StartStopArgs {
            name: "ntfy".into(),
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    assert!(m.seen.lock().unwrap().iter().all(|s| s.method == "GET"));

    let get = serde_json::to_string(&show_app(false)).unwrap();
    let m = mock(move |_, _| (200, get.clone())).await;
    let code = apps_stop(
        true,
        &overrides(&m),
        StartStopArgs {
            name: "ntfy".into(),
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    assert!(m.seen.lock().unwrap().iter().all(|s| s.method == "GET"));
}

#[tokio::test(flavor = "current_thread")]
async fn start_dry_run_sends_nothing() {
    let get = serde_json::to_string(&show_app(false)).unwrap();
    let m = mock(move |_, _| (200, get.clone())).await;
    let code = apps_start(
        true,
        &overrides(&m),
        StartStopArgs {
            name: "ntfy".into(),
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    assert!(m.seen.lock().unwrap().iter().all(|s| s.method == "GET"));
}

// ---------- apps remove / secrets remove (issue #80) ----------

/// `apps remove` flags as parsed from the command line.
fn remove_args(extra: &[&str]) -> RemoveArgs {
    #[derive(clap::Parser)]
    struct Rm {
        #[command(flatten)]
        a: RemoveArgs,
    }
    let mut argv = vec!["remove", "ntfy"];
    argv.extend_from_slice(extra);
    Rm::try_parse_from(argv).unwrap().a
}

/// `secrets remove` flags as parsed from the command line.
fn secret_remove_args(extra: &[&str]) -> SecretRemoveArgs {
    #[derive(clap::Parser)]
    struct Rm {
        #[command(flatten)]
        a: SecretRemoveArgs,
    }
    let mut argv = vec!["remove", "ntfy", "token"];
    argv.extend_from_slice(extra);
    Rm::try_parse_from(argv).unwrap().a
}

#[test]
fn apps_remove_query_joins_the_purge_flags() {
    assert_eq!(remove_query(&remove_args(&[])), "");
    assert_eq!(
        remove_query(&remove_args(&["--purge-volumes"])),
        "purge_volumes=true"
    );
    assert_eq!(
        remove_query(&remove_args(&["--purge-secrets"])),
        "purge_secrets=true"
    );
    assert_eq!(
        remove_query(&remove_args(&["--purge-secrets", "--purge-volumes"])),
        "purge_volumes=true&purge_secrets=true"
    );
    // The human line says what was deleted along with the app.
    assert_eq!(remove_suffix(&remove_args(&[])), "");
    assert_eq!(
        remove_suffix(&remove_args(&["--purge-volumes"])),
        " (with its data)"
    );
    assert_eq!(
        remove_suffix(&remove_args(&["--purge-secrets"])),
        " (with its secrets)"
    );
    assert_eq!(
        remove_suffix(&remove_args(&["--purge-volumes", "--purge-secrets"])),
        " (with its data and secrets)"
    );
}

#[test]
fn apps_remove_dry_run_shows_the_query() {
    assert_eq!(
        remove_dry_run("ntfy", &remove_args(&[])).path,
        "/v1/apps/ntfy"
    );
    assert_eq!(
        remove_dry_run("ntfy", &remove_args(&["--purge-volumes"])).path,
        "/v1/apps/ntfy?purge_volumes=true"
    );
    assert_eq!(
        remove_dry_run(
            "ntfy",
            &remove_args(&["--purge-volumes", "--purge-secrets"])
        )
        .path,
        "/v1/apps/ntfy?purge_volumes=true&purge_secrets=true"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn apps_remove_sends_both_purge_flags_and_the_dry_run_sends_nothing() {
    // `--dry-run` only checks that the app exists (GET) and prints the query.
    let get = serde_json::to_string(&show_app(true)).unwrap();
    let m = mock(move |_, _| (200, get.clone())).await;
    let code = apps_remove(
        true,
        &overrides(&m),
        remove_args(&["--purge-volumes", "--purge-secrets", "--dry-run"]),
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    {
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("GET", "/v1/apps/ntfy")
        );
    }

    let m = mock(|_, _| (204, String::new())).await;
    let code = apps_remove(
        true,
        &overrides(&m),
        remove_args(&["--purge-volumes", "--purge-secrets"]),
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("DELETE", "/v1/apps/ntfy")
    );
    assert_eq!(
        seen[0].query.as_deref(),
        Some("purge_volumes=true&purge_secrets=true")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn apps_remove_sends_purge_volumes_only_when_asked() {
    for (purge_volumes, expected) in [(true, Some("purge_volumes=true")), (false, None)] {
        let m = mock(|_, _| (204, String::new())).await;
        let code = apps_remove(
            true,
            &overrides(&m),
            RemoveArgs {
                name: "ntfy".into(),
                ignore_missing: false,
                purge_volumes,
                purge_secrets: false,
                dry_run: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "DELETE");
        assert_eq!(seen[0].query.as_deref(), expected);
    }
}

#[test]
fn clap_parses_secrets_remove_without_a_value_argument() {
    use crate::cli::{Cli, Command, SecretsCommand};
    use clap::Parser;

    let cli = Cli::try_parse_from(["weglarka", "secrets", "remove", "ntfy", "token"]).unwrap();
    match cli.command {
        Command::Secrets(SecretsCommand::Remove(a)) => {
            assert_eq!((a.app.as_str(), a.name.as_str()), ("ntfy", "token"));
            assert!(!a.force);
            assert!(!a.dry_run);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "weglarka",
        "secrets",
        "remove",
        "ntfy",
        "token",
        "--force",
        "--dry-run",
    ])
    .unwrap();
    match cli.command {
        Command::Secrets(SecretsCommand::Remove(a)) => {
            assert!(a.force);
            assert!(a.dry_run);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    // A value argument is rejected, as for `secrets set`: values never reach the command line.
    assert!(
        Cli::try_parse_from(["weglarka", "secrets", "remove", "ntfy", "token", "hunter2"]).is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn secrets_remove_deletes_without_and_with_force() {
    let m = mock(|_, _| (204, String::new())).await;
    let code = secrets_remove(true, &overrides(&m), secret_remove_args(&[]))
        .await
        .unwrap();
    assert_eq!(code, exit::OK);
    {
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("DELETE", "/v1/apps/ntfy/secrets/token")
        );
        assert_eq!(seen[0].query, None);
    }

    // `--force` is the `force=true` query; the app itself need not exist (no GET first).
    let m = mock(|_, _| (204, String::new())).await;
    let code = secrets_remove(true, &overrides(&m), secret_remove_args(&["--force"]))
        .await
        .unwrap();
    assert_eq!(code, exit::OK);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("DELETE", "/v1/apps/ntfy/secrets/token")
    );
    assert_eq!(seen[0].query.as_deref(), Some("force=true"));
}

#[tokio::test(flavor = "current_thread")]
async fn secrets_remove_dry_run_sends_nothing_and_shows_force() {
    // No server lookup at all: `--dry-run` must work for an app that was already removed.
    let m = mock(|_, _| (204, String::new())).await;
    let code = secrets_remove(
        true,
        &overrides(&m),
        secret_remove_args(&["--force", "--dry-run"]),
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    assert!(m.seen.lock().unwrap().is_empty());
    assert_eq!(
        secret_remove_dry_run("ntfy", "token", false).path,
        "/v1/apps/ntfy/secrets/token"
    );
    assert_eq!(
        secret_remove_dry_run("ntfy", "token", true).path,
        "/v1/apps/ntfy/secrets/token?force=true"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn secrets_remove_maps_conflict_and_not_found_to_hints() {
    let m = mock(|_, _| {
        (
            409,
            api_err(
                ErrorCode::Conflict,
                "the app's spec still binds secret token",
            ),
        )
    })
    .await;
    let err = secrets_remove(true, &overrides(&m), secret_remove_args(&[]))
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::Conflict);
    let hint = err.hint.unwrap();
    assert!(hint.contains("--unbind-secret token"), "{hint}");
    assert!(hint.contains("--force"), "{hint}");

    let m = mock(|_, _| (404, api_err(ErrorCode::NotFound, "no such secret"))).await;
    let err = secrets_remove(true, &overrides(&m), secret_remove_args(&[]))
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::NotFound);
    assert_eq!(
        err.hint.as_deref(),
        Some("check the stored secrets: `weglarka secrets list ntfy`")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn secrets_remove_validates_names_locally() {
    let m = mock(|_, _| (204, String::new())).await;
    let o = overrides(&m);
    let mut a = secret_remove_args(&[]);
    a.name = "bad name".into();
    assert_eq!(
        secrets_remove(true, &o, a).await.unwrap_err().exit_code(),
        exit::USAGE
    );
    let mut a = secret_remove_args(&[]);
    a.app = "Bad Name".into();
    assert_eq!(
        secrets_remove(true, &o, a).await.unwrap_err().exit_code(),
        exit::USAGE
    );
    assert!(m.seen.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test(flavor = "current_thread")]
async fn images_prune_sends_the_dry_run_flag_and_renders_the_report() {
    let response = serde_json::to_string(&PruneImagesResponse {
        dry_run: true,
        removed: vec![PrunedImage {
            id: "a".repeat(64),
            tags: Vec::new(),
            digests: vec![format!("ghcr.io/x/y@sha256:{}", "b".repeat(64))],
            size_bytes: 5 * 1024 * 1024,
        }],
        reclaimed_bytes: 5 * 1024 * 1024,
        failed: Vec::new(),
    })
    .unwrap();
    let m = mock(move |_, _| (200, response.clone())).await;
    let code = crate::commands::images_prune(
        true,
        &overrides(&m),
        crate::cli::PruneImagesArgs { dry_run: true },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::OK);
    {
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("POST", "/v1/images/prune")
        );
        assert_eq!(seen[0].body, r#"{"dry_run":true}"#);
    }

    let report = PruneImagesResponse {
        dry_run: true,
        removed: vec![PrunedImage {
            id: "a".repeat(64),
            tags: Vec::new(),
            digests: vec![format!("ghcr.io/x/y@sha256:{}", "b".repeat(64))],
            size_bytes: 5 * 1024 * 1024,
        }],
        reclaimed_bytes: 5 * 1024 * 1024,
        failed: Vec::new(),
    };
    let rendered = crate::commands::render_prune(&report);
    assert!(
        rendered.contains("would remove 1 image(s), 5.0 MiB at most"),
        "{rendered}"
    );
    assert!(rendered.contains("aaaaaaaaaaaa"), "short id: {rendered}");
    assert!(
        rendered.contains("ghcr.io/x/y@sha256:bbbbbbbbbbbb…"),
        "an untagged leftover is named by its digest: {rendered}"
    );
}

/// Images Podman refused are reported and turn the exit code non-zero (they need attention).
#[tokio::test(flavor = "current_thread")]
async fn images_prune_with_failures_exits_non_zero() {
    let response = serde_json::to_string(&PruneImagesResponse {
        dry_run: false,
        removed: Vec::new(),
        reclaimed_bytes: 0,
        failed: vec!["deadbeef: image is in use by a container".to_owned()],
    })
    .unwrap();
    let m = mock(move |_, _| (200, response.clone())).await;
    let code = crate::commands::images_prune(
        true,
        &overrides(&m),
        crate::cli::PruneImagesArgs { dry_run: false },
    )
    .await
    .unwrap();
    assert_eq!(code, exit::INTERNAL);
    assert_eq!(m.seen.lock().unwrap()[0].body, r#"{"dry_run":false}"#);
}

#[test]
fn runtime_labels_cover_the_lifecycle() {
    assert_eq!(runtime_label(RuntimeState::NotStarted), "not-started");
    assert_eq!(runtime_label(RuntimeState::Running), "running");
    assert_eq!(runtime_label(RuntimeState::Stopped), "stopped");
    assert_eq!(
        runtime_label(RuntimeState::WaitingForSecret),
        "waiting-for-secret"
    );
}

// ---------- notifications (issue #38) ----------

fn notify_status_body(enabled: bool) -> String {
    serde_json::json!({
        "enabled": enabled,
        "channels": if enabled {
            serde_json::json!([{ "name": "ntfy", "min_severity": "warning", "pending": 2 }])
        } else {
            serde_json::json!([])
        },
        "pending": if enabled { 2 } else { 0 },
        "dropped": if enabled { 1 } else { 0 },
        "last_error": if enabled { Some("ntfy answered 500") } else { None },
        "last_delivered_at": if enabled { Some("2026-10-24T13:40:00Z") } else { None }
    })
    .to_string()
}

#[tokio::test(flavor = "current_thread")]
async fn notify_status_and_test_call_the_documented_endpoints() {
    let m = mock(|method, path| match (method, path) {
        ("GET", "/v1/notifications") => (200, notify_status_body(true)),
        ("POST", "/v1/notifications/test") => (
            200,
            serde_json::json!({ "delivered": false, "error": "ntfy refused the access token" })
                .to_string(),
        ),
        _ => (404, api_err(ErrorCode::NotFound, "no such endpoint")),
    })
    .await;

    let code = notify_status(true, &overrides(&m)).await.unwrap();
    assert_eq!(code, exit::OK);
    let code = notify_test(true, &overrides(&m)).await.unwrap();
    assert_eq!(code, exit::NOTIFY_FAILED, "a refused test is a failure");

    let seen = m.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("GET", "/v1/notifications")
    );
    assert_eq!(
        (seen[1].method.as_str(), seen[1].path.as_str()),
        ("POST", "/v1/notifications/test")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_delivered_notify_test_exits_zero() {
    let m = mock(|_, _| (200, serde_json::json!({ "delivered": true }).to_string())).await;
    assert_eq!(notify_test(true, &overrides(&m)).await.unwrap(), exit::OK);
}

#[test]
fn notify_status_rendering_covers_off_pending_and_errors() {
    let off: NotifyStatusResponse = serde_json::from_str(&notify_status_body(false)).unwrap();
    let rendered = render_notify_status(&off);
    assert!(rendered.contains("notifications: off"), "{rendered}");

    let on: NotifyStatusResponse = serde_json::from_str(&notify_status_body(true)).unwrap();
    let rendered = render_notify_status(&on);
    assert!(
        rendered.contains("ntfy: min severity warning"),
        "{rendered}"
    );
    assert!(rendered.contains("2 notifications queued"), "{rendered}");
    assert!(
        rendered.contains("outbox: 2 pending, 1 dropped"),
        "{rendered}"
    );
    assert!(
        rendered.contains("last delivered: 2026-10-24T13:40:00Z"),
        "{rendered}"
    );
    assert!(
        rendered.contains("last error: ntfy answered 500"),
        "{rendered}"
    );
}
