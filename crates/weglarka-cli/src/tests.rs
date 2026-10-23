//! Tests: the client against a mock server (unix socket), preflight on a fake host, exit codes.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use weglarka_api::{
    ApiError, DeployOutcome, DeployResponse, DoctorReport, ErrorCode, SetSecretRequest, endpoints,
};
use weglarka_core::config::HostConfig;

use crate::client::{ApiClient, expand_path};
use crate::commands::read_secret_value;
use crate::error::{CliError, Kind, exit};
use crate::preflight::host::{CmdOutput, FileKind};
use crate::preflight::testing::FakeHost;
use crate::preflight::{Context, all_checks, render, run_checks};

// ---------- mock server on a unix socket ----------

#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) path: String,
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
                        let host = req
                            .headers()
                            .get("host")
                            .map(|h| h.to_str().unwrap().to_owned());
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        seen.lock().unwrap().push(Seen {
                            method: method.clone(),
                            path: path.clone(),
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
        (ErrorCode::Internal, exit::INTERNAL),
    ] {
        let m = mock(move |_, _| (code.http_status(), api_err(code, "boom"))).await;
        let err = ApiClient::new(&m.socket)
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
fn edge_mode_skips_traefik_check_and_openrc_skips_linger() {
    let cfg = CONFIG
        .replace("behind", "edge")
        .replace("\n[webhook]", "\n[platform]\nkind = \"openrc\"\n[webhook]");
    let r = report(&FakeHost::healthy(), Some(&cfg));
    let ids: Vec<_> = r.checks.iter().map(|c| c.id.as_str()).collect();
    assert!(!ids.contains(&"ingress.traefik_file"));
    assert!(!ids.contains(&"runtime.linger"));
}

// ---------- new host checks (devops, niechybnie) ----------

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
